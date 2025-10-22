package auth

import (
	"fmt"
	"kiro2api/config"
	"kiro2api/logger"
	"kiro2api/types"
	"sync"
	"time"
)

// PersistFunc 持久化函数类型
// 用于将token持久化到存储（避免循环依赖）
type PersistFunc func(token types.TokenInfo, authConfig AuthConfig, configIndex int, tokensDir string) error

// TokenManager 简化的token管理器（支持后台刷新）
type TokenManager struct {
	cache         *SimpleTokenCache
	configs       []AuthConfig
	mutex         sync.RWMutex    // 使用读写锁优化并发性能
	lastRefresh   time.Time
	configOrder   []string        // 配置顺序
	currentIndex  int             // 当前使用的token索引
	exhausted     map[string]bool // 已耗尽的token记录
	tokensDir     string          // tokens文件存储目录
	refreshTicker *time.Ticker    // 后台刷新定时器
	stopChan      chan struct{}   // 停止信号
	persistFunc   PersistFunc     // 持久化回调函数（可选）
}

// SimpleTokenCache 简化的token缓存（纯数据结构，无锁）
// 所有并发访问由 TokenManager.mutex 统一管理
type SimpleTokenCache struct {
	tokens map[string]*CachedToken
	ttl    time.Duration
}

// CachedToken 缓存的token信息
type CachedToken struct {
	Token     types.TokenInfo
	UsageInfo *types.UsageLimits
	CachedAt  time.Time
	LastUsed  time.Time
	Available float64
}

// NewSimpleTokenCache 创建简单的token缓存
func NewSimpleTokenCache(ttl time.Duration) *SimpleTokenCache {
	return &SimpleTokenCache{
		tokens: make(map[string]*CachedToken),
		ttl:    ttl,
	}
}

// NewTokenManager 创建新的token管理器
func NewTokenManager(configs []AuthConfig, tokensDir string) *TokenManager {
	// 生成配置顺序
	configOrder := generateConfigOrder(configs)

	logger.Info("TokenManager初始化（顺序选择策略 + 后台刷新）",
		logger.Int("config_count", len(configs)),
		logger.Int("config_order_count", len(configOrder)),
		logger.String("tokens_dir", tokensDir))

	tm := &TokenManager{
		cache:        NewSimpleTokenCache(config.TokenCacheTTL),
		configs:      configs,
		configOrder:  configOrder,
		currentIndex: 0,
		exhausted:    make(map[string]bool),
		tokensDir:    tokensDir,
		stopChan:     make(chan struct{}),
		persistFunc:  nil, // 默认不持久化，由调用者通过 SetPersistFunc 设置
	}

	// 立即执行一次初始刷新（确保cache可用）
	// 这避免了服务启动后前60秒内所有请求失败的问题
	if len(configs) > 0 {
		logger.Info("执行初始token刷新")
		if err := tm.refreshCacheUnlocked(); err != nil {
			logger.Warn("初始token刷新失败", logger.Err(err))
		} else {
			logger.Info("初始token刷新完成",
				logger.Int("cached_tokens", len(tm.cache.tokens)))
		}
	}

	return tm
}

// SetPersistFunc 设置持久化回调函数（可选，用于自定义持久化逻辑）
func (tm *TokenManager) SetPersistFunc(fn PersistFunc) {
	tm.persistFunc = fn
}

// getBestToken 获取最优可用token
// 使用读锁优化并发性能（刷新由后台任务负责）
func (tm *TokenManager) getBestToken() (types.TokenInfo, error) {
	tm.mutex.Lock() // 需要写锁因为要更新 LastUsed 和 Available
	defer tm.mutex.Unlock()

	// 防御性检查：如果cache为空，立即刷新（启动失败的兜底逻辑）
	if len(tm.cache.tokens) == 0 {
		logger.Warn("检测到空cache，立即执行紧急刷新")
		if err := tm.refreshCacheUnlocked(); err != nil {
			logger.Error("紧急刷新失败", logger.Err(err))
			return types.TokenInfo{}, fmt.Errorf("token池未初始化且刷新失败: %w", err)
		}
		logger.Info("紧急刷新完成", logger.Int("cached_tokens", len(tm.cache.tokens)))
	}

	// 选择最优token（内部方法，不加锁）
	bestToken := tm.selectBestTokenUnlocked()
	if bestToken == nil {
		return types.TokenInfo{}, fmt.Errorf("没有可用的token")
	}

	// 更新最后使用时间（在锁内，安全）
	bestToken.LastUsed = time.Now()
	if bestToken.Available > 0 {
		bestToken.Available--
	}

	return bestToken.Token, nil
}

// GetBestTokenWithUsage 获取最优可用token（包含使用信息）
// 使用读锁优化并发性能（刷新由后台任务负责）
func (tm *TokenManager) GetBestTokenWithUsage() (*types.TokenWithUsage, error) {
	tm.mutex.Lock() // 需要写锁因为要更新 LastUsed 和 Available
	defer tm.mutex.Unlock()

	// 防御性检查：如果cache为空，立即刷新（启动失败的兜底逻辑）
	if len(tm.cache.tokens) == 0 {
		logger.Warn("检测到空cache，立即执行紧急刷新")
		if err := tm.refreshCacheUnlocked(); err != nil {
			logger.Error("紧急刷新失败", logger.Err(err))
			return nil, fmt.Errorf("token池未初始化且刷新失败: %w", err)
		}
		logger.Info("紧急刷新完成", logger.Int("cached_tokens", len(tm.cache.tokens)))
	}

	// 选择最优token（内部方法，不加锁）
	bestToken := tm.selectBestTokenUnlocked()
	if bestToken == nil {
		return nil, fmt.Errorf("没有可用的token")
	}

	// 更新最后使用时间（在锁内，安全）
	bestToken.LastUsed = time.Now()
	available := bestToken.Available
	if bestToken.Available > 0 {
		bestToken.Available--
	}

	// 构造 TokenWithUsage
	tokenWithUsage := &types.TokenWithUsage{
		TokenInfo:       bestToken.Token,
		UsageLimits:     bestToken.UsageInfo,
		AvailableCount:  available, // 使用精确计算的可用次数
		LastUsageCheck:  bestToken.LastUsed,
		IsUsageExceeded: available <= 0,
	}

	logger.Debug("返回TokenWithUsage",
		logger.Float64("available_count", available),
		logger.Bool("is_exceeded", tokenWithUsage.IsUsageExceeded))

	return tokenWithUsage, nil
}

// selectBestTokenUnlocked 按配置顺序选择下一个可用token
// 内部方法：调用者必须持有 tm.mutex
// 重构说明：从selectBestToken改为Unlocked后缀，明确锁约定
func (tm *TokenManager) selectBestTokenUnlocked() *CachedToken {
	// 调用者已持有 tm.mutex，无需额外加锁

	// 如果没有配置顺序，降级到按map遍历顺序
	if len(tm.configOrder) == 0 {
		for key, cached := range tm.cache.tokens {
			if time.Since(cached.CachedAt) <= tm.cache.ttl && cached.IsUsable() {
				logger.Debug("顺序策略选择token（无顺序配置）",
					logger.String("selected_key", key),
					logger.Float64("available_count", cached.Available))
				return cached
			}
		}
		return nil
	}

	// 从当前索引开始，找到第一个可用的token
	for attempts := 0; attempts < len(tm.configOrder); attempts++ {
		currentKey := tm.configOrder[tm.currentIndex]

		// 检查这个token是否存在且可用
		if cached, exists := tm.cache.tokens[currentKey]; exists {
			// 检查token是否过期
			if time.Since(cached.CachedAt) > tm.cache.ttl {
				tm.exhausted[currentKey] = true
				tm.currentIndex = (tm.currentIndex + 1) % len(tm.configOrder)
				continue
			}

			// 检查token是否可用
			if cached.IsUsable() {
				logger.Debug("顺序策略选择token",
					logger.String("selected_key", currentKey),
					logger.Int("index", tm.currentIndex),
					logger.Float64("available_count", cached.Available))
				return cached
			}
		}

		// 标记当前token为已耗尽，移动到下一个
		tm.exhausted[currentKey] = true
		tm.currentIndex = (tm.currentIndex + 1) % len(tm.configOrder)

		logger.Debug("token不可用，切换到下一个",
			logger.String("exhausted_key", currentKey),
			logger.Int("next_index", tm.currentIndex))
	}

	// 所有token都不可用
	logger.Warn("所有token都不可用",
		logger.Int("total_count", len(tm.configOrder)),
		logger.Int("exhausted_count", len(tm.exhausted)))

	return nil
}

// refreshCacheUnlocked 刷新token缓存
// 内部方法：调用者必须持有 tm.mutex
func (tm *TokenManager) refreshCacheUnlocked() error {
	logger.Debug("开始刷新token缓存")

	for i, cfg := range tm.configs {
		if cfg.Disabled {
			continue
		}

		// 刷新token
		token, err := tm.refreshSingleToken(cfg)
		if err != nil {
			logger.Warn("刷新单个token失败",
				logger.Int("config_index", i),
				logger.String("auth_type", cfg.AuthType),
				logger.Err(err))
			continue
		}

		// 检查使用限制
		var usageInfo *types.UsageLimits
		var available float64

		checker := NewUsageLimitsChecker()
		if usage, checkErr := checker.CheckUsageLimits(token); checkErr == nil {
			usageInfo = usage
			available = CalculateAvailableCount(usage)
		} else {
			logger.Warn("检查使用限制失败", logger.Err(checkErr))
		}

		// 更新缓存（直接访问，已在tm.mutex保护下）
		cacheKey := fmt.Sprintf(config.TokenCacheKeyFormat, i)
		tm.cache.tokens[cacheKey] = &CachedToken{
			Token:     token,
			UsageInfo: usageInfo,
			CachedAt:  time.Now(),
			Available: available,
		}

		logger.Debug("token缓存更新",
			logger.String("cache_key", cacheKey),
			logger.Float64("available", available))
	}

	tm.lastRefresh = time.Now()
	return nil
}

// IsUsable 检查缓存的token是否可用
func (ct *CachedToken) IsUsable() bool {
	// 检查token是否过期
	if time.Now().After(ct.Token.ExpiresAt) {
		return false
	}

	// 检查可用次数
	return ct.Available > 0
}

// *** 已删除 set 和 updateLastUsed 方法 ***
// SimpleTokenCache 现在是纯数据结构，所有访问由 TokenManager.mutex 保护
// set 操作：直接通过 tm.cache.tokens[key] = value 完成
// updateLastUsed 操作：已合并到 getBestToken 方法中

// CalculateAvailableCount 计算可用次数 (基于CREDIT资源类型，返回浮点精度)
func CalculateAvailableCount(usage *types.UsageLimits) float64 {
	for _, breakdown := range usage.UsageBreakdownList {
		if breakdown.ResourceType == "CREDIT" {
			var totalAvailable float64

			// 优先使用免费试用额度 (如果存在且处于ACTIVE状态)
			if breakdown.FreeTrialInfo != nil && breakdown.FreeTrialInfo.FreeTrialStatus == "ACTIVE" {
				freeTrialAvailable := breakdown.FreeTrialInfo.UsageLimitWithPrecision - breakdown.FreeTrialInfo.CurrentUsageWithPrecision
				totalAvailable += freeTrialAvailable
			}

			// 加上基础额度
			baseAvailable := breakdown.UsageLimitWithPrecision - breakdown.CurrentUsageWithPrecision
			totalAvailable += baseAvailable

			if totalAvailable < 0 {
				return 0.0
			}
			return totalAvailable
		}
	}
	return 0.0
}

// generateConfigOrder 生成token配置的顺序
func generateConfigOrder(configs []AuthConfig) []string {
	var order []string

	for i := range configs {
		// 使用索引生成cache key，与refreshCache中的逻辑保持一致
		cacheKey := fmt.Sprintf(config.TokenCacheKeyFormat, i)
		order = append(order, cacheKey)
	}

	logger.Debug("生成配置顺序",
		logger.Int("config_count", len(configs)),
		logger.Any("order", order))

	return order
}

// ========== 后台刷新功能 ==========

// StartBackgroundRefresh 启动后台刷新goroutine
func (tm *TokenManager) StartBackgroundRefresh() {
	tm.refreshTicker = time.NewTicker(config.BackgroundRefreshInterval)

	go tm.backgroundRefreshLoop()

	logger.Info("后台token刷新已启动",
		logger.Duration("check_interval", config.BackgroundRefreshInterval),
		logger.Duration("refresh_window", config.TokenRefreshWindow))
}

// StopBackgroundRefresh 停止后台刷新
func (tm *TokenManager) StopBackgroundRefresh() {
	if tm.refreshTicker != nil {
		tm.refreshTicker.Stop()
	}

	// 发送停止信号
	select {
	case tm.stopChan <- struct{}{}:
	default:
		// stopChan 可能已关闭或已满，忽略
	}

	logger.Info("后台token刷新停止信号已发送")
}

// backgroundRefreshLoop 后台刷新循环
func (tm *TokenManager) backgroundRefreshLoop() {
	logger.Debug("后台刷新goroutine已启动")

	for {
		select {
		case <-tm.refreshTicker.C:
			logger.Debug("执行定时token检查")
			tm.checkAndRefreshTokens()

		case <-tm.stopChan:
			logger.Info("后台刷新goroutine已停止")
			return
		}
	}
}

// checkAndRefreshTokens 检查并刷新需要刷新的tokens
func (tm *TokenManager) checkAndRefreshTokens() {
	// 第一步：找出需要刷新的token（使用读锁）
	tm.mutex.RLock()
	tokensToRefresh := tm.findTokensNeedingRefreshUnlocked()
	tm.mutex.RUnlock()

	if len(tokensToRefresh) == 0 {
		logger.Debug("没有token需要刷新")
		return
	}

	logger.Info("发现需要刷新的token", logger.Int("count", len(tokensToRefresh)))

	// 第二步：刷新这些token（不持有锁，避免阻塞）
	for _, configWithIndex := range tokensToRefresh {
		tm.refreshSingleTokenWithRetry(configWithIndex.config, configWithIndex.index)
	}
}

// configWithIndex 配置和索引的包装
type configWithIndex struct {
	config AuthConfig
	index  int
}

// findTokensNeedingRefreshUnlocked 找出需要刷新的tokens
// 内部方法：调用者必须持有 tm.mutex (读锁即可)
func (tm *TokenManager) findTokensNeedingRefreshUnlocked() []configWithIndex {
	var tokensToRefresh []configWithIndex

	for i, cfg := range tm.configs {
		if cfg.Disabled {
			continue
		}

		cacheKey := fmt.Sprintf(config.TokenCacheKeyFormat, i)
		cached, exists := tm.cache.tokens[cacheKey]

		// 如果token不存在或需要刷新
		if !exists || tm.shouldRefreshToken(cached) {
			tokensToRefresh = append(tokensToRefresh, configWithIndex{
				config: cfg,
				index:  i,
			})
		}
	}

	return tokensToRefresh
}

// shouldRefreshToken 判断token是否需要刷新
// 提前10分钟刷新，而不是等到过期
func (tm *TokenManager) shouldRefreshToken(cached *CachedToken) bool {
	if cached == nil {
		return true
	}

	// 检查token是否在刷新窗口内（提前10分钟）
	timeUntilExpiry := time.Until(cached.Token.ExpiresAt)
	return timeUntilExpiry <= config.TokenRefreshWindow
}

// refreshSingleTokenWithRetry 刷新单个token（带指数退避重试）
func (tm *TokenManager) refreshSingleTokenWithRetry(authConfig AuthConfig, configIndex int) {
	var lastErr error

	for attempt := 0; attempt <= config.MaxRefreshRetries; attempt++ {
		// 执行刷新
		token, err := tm.refreshSingleToken(authConfig)
		if err == nil {
			// 成功：更新缓存并持久化
			tm.updateCacheAndPersist(authConfig, token, configIndex)
			logger.Info("token刷新成功",
				logger.Int("config_index", configIndex),
				logger.String("auth_type", authConfig.AuthType),
				logger.Int("attempt", attempt+1))
			return
		}

		lastErr = err
		logger.Warn("token刷新失败",
			logger.Int("config_index", configIndex),
			logger.String("auth_type", authConfig.AuthType),
			logger.Int("attempt", attempt+1),
			logger.Err(err))

		// 如果还有重试机会，等待后重试
		if attempt < config.MaxRefreshRetries {
			delay := config.RefreshRetryBaseDelay * time.Duration(1<<uint(attempt))
			logger.Debug("等待后重试", logger.Duration("delay", delay))
			time.Sleep(delay)
		}
	}

	logger.Error("token刷新失败（已达最大重试次数）",
		logger.Int("config_index", configIndex),
		logger.String("auth_type", authConfig.AuthType),
		logger.Int("max_retries", config.MaxRefreshRetries),
		logger.Err(lastErr))
}

// updateCacheAndPersist 更新缓存并持久化到文件
func (tm *TokenManager) updateCacheAndPersist(authConfig AuthConfig, token types.TokenInfo, configIndex int) {
	// 检查使用限制
	var usageInfo *types.UsageLimits
	var available float64

	checker := NewUsageLimitsChecker()
	if usage, checkErr := checker.CheckUsageLimits(token); checkErr == nil {
		usageInfo = usage
		available = CalculateAvailableCount(usage)
	} else {
		logger.Warn("检查使用限制失败", logger.Err(checkErr))
	}

	// 更新缓存（需要写锁）
	tm.mutex.Lock()
	cacheKey := fmt.Sprintf(config.TokenCacheKeyFormat, configIndex)
	tm.cache.tokens[cacheKey] = &CachedToken{
		Token:     token,
		UsageInfo: usageInfo,
		CachedAt:  time.Now(),
		Available: available,
	}
	tm.lastRefresh = time.Now()
	// 清除exhausted标记
	delete(tm.exhausted, cacheKey)
	tm.mutex.Unlock()

	logger.Debug("token缓存已更新",
		logger.String("cache_key", cacheKey),
		logger.Float64("available", available))

	// 持久化到文件（不需要锁）
	if err := tm.persistTokenToFile(token, authConfig, configIndex); err != nil {
		logger.Warn("token持久化失败", logger.Err(err))
	}
}

// persistTokenToFile 持久化token到文件
func (tm *TokenManager) persistTokenToFile(token types.TokenInfo, authConfig AuthConfig, configIndex int) error {
	// 如果设置了持久化回调函数，则调用它
	if tm.persistFunc != nil {
		return tm.persistFunc(token, authConfig, configIndex, tm.tokensDir)
	}
	// 如果没有设置，跳过持久化（仅内存）
	return nil
}

// GetHealthInfo 获取健康信息
// 返回：总token数，可用token数，最后刷新时间
func (tm *TokenManager) GetHealthInfo() (int, int, time.Time) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	totalTokens := len(tm.configs)
	availableTokens := 0

	for _, cached := range tm.cache.tokens {
		if cached.IsUsable() {
			availableTokens++
		}
	}

	return totalTokens, availableTokens, tm.lastRefresh
}
