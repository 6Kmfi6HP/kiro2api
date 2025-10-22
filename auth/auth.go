package auth

import (
	"fmt"
	"kiro2api/logger"
	"kiro2api/types"
	"os"
)

// AuthService 认证服务（推荐使用依赖注入方式）
type AuthService struct {
	tokenManager *TokenManager
	configs      []AuthConfig
	tokensDir    string // tokens文件存储目录
}

// NewAuthService 创建新的认证服务（推荐使用此方法而不是全局函数）
func NewAuthService() (*AuthService, error) {
	logger.Info("创建AuthService实例")

	// 读取tokens目录配置
	tokensDir := os.Getenv("KIRO_TOKENS_DIR")
	if tokensDir == "" {
		tokensDir = "tokens" // 默认目录
	}
	logger.Info("使用tokens目录", logger.String("tokens_dir", tokensDir))

	// 加载配置
	configs, err := loadConfigs()
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	// 允许零配置启动（用于dashboard添加token）
	if len(configs) == 0 {
		logger.Warn("未找到任何token配置，服务将以空token池启动")
		logger.Warn("请通过dashboard添加token或配置KIRO_AUTH_TOKEN环境变量")
	}

	// 创建token管理器（传入tokensDir）
	tokenManager := NewTokenManager(configs, tokensDir)

	// 仅在有配置时预热token
	if len(configs) > 0 {
		_, warmupErr := tokenManager.getBestToken()
		if warmupErr != nil {
			logger.Warn("token预热失败", logger.Err(warmupErr))
		}
	}

	// 启动后台刷新
	tokenManager.StartBackgroundRefresh()
	logger.Info("后台token刷新已启动")

	logger.Info("AuthService创建完成", logger.Int("config_count", len(configs)))

	return &AuthService{
		tokenManager: tokenManager,
		configs:      configs,
		tokensDir:    tokensDir,
	}, nil
}

// GetToken 获取可用的token
func (as *AuthService) GetToken() (types.TokenInfo, error) {
	if as.tokenManager == nil {
		return types.TokenInfo{}, fmt.Errorf("token管理器未初始化")
	}
	return as.tokenManager.getBestToken()
}

// GetTokenWithUsage 获取可用的token（包含使用信息）
func (as *AuthService) GetTokenWithUsage() (*types.TokenWithUsage, error) {
	if as.tokenManager == nil {
		return nil, fmt.Errorf("token管理器未初始化")
	}
	return as.tokenManager.GetBestTokenWithUsage()
}

// GetTokenManager 获取底层的TokenManager（用于高级操作）
func (as *AuthService) GetTokenManager() *TokenManager {
	return as.tokenManager
}

// GetConfigs 获取认证配置
func (as *AuthService) GetConfigs() []AuthConfig {
	return as.configs
}

// AddToken 动态添加新的token配置
// 用于dashboard登录后添加token到运行中的服务
func (as *AuthService) AddToken(config AuthConfig) error {
	if as.tokenManager == nil {
		return fmt.Errorf("token管理器未初始化")
	}

	// 验证配置
	if config.RefreshToken == "" {
		return fmt.Errorf("refreshToken不能为空")
	}

	// 设置默认认证类型
	if config.AuthType == "" {
		config.AuthType = AuthMethodSocial
	}

	// 验证IdC认证的必要字段
	if config.AuthType == AuthMethodIdC {
		if config.ClientID == "" || config.ClientSecret == "" {
			return fmt.Errorf("IdC认证缺少clientId或clientSecret")
		}
	}

	// 添加到配置列表
	as.configs = append(as.configs, config)

	// 停止旧的后台刷新
	if as.tokenManager != nil {
		as.tokenManager.StopBackgroundRefresh()
	}

	// 重新创建TokenManager以包含新配置
	as.tokenManager = NewTokenManager(as.configs, as.tokensDir)

	// 重新启动后台刷新
	as.tokenManager.StartBackgroundRefresh()

	logger.Info("动态添加token成功",
		logger.String("auth_type", config.AuthType),
		logger.Int("total_configs", len(as.configs)))

	return nil
}

// ReloadTokensFromDirectory 从tokens目录重新加载所有token
// 用于dashboard添加token后刷新服务中的token池
func (as *AuthService) ReloadTokensFromDirectory(tokensDir string) error {
	if tokensDir == "" {
		tokensDir = "tokens"
	}

	// 从目录加载token配置
	fileConfigs, err := LoadTokensFromDirectory(tokensDir)
	if err != nil {
		return fmt.Errorf("从tokens目录加载配置失败: %w", err)
	}

	if len(fileConfigs) == 0 {
		logger.Warn("tokens目录中没有找到有效的token配置",
			logger.String("目录", tokensDir))
		return nil
	}

	// 合并现有配置和文件配置（去重）
	existingTokens := make(map[string]bool)
	for _, config := range as.configs {
		existingTokens[config.RefreshToken] = true
	}

	newConfigs := 0
	for _, config := range fileConfigs {
		if !existingTokens[config.RefreshToken] {
			as.configs = append(as.configs, config)
			newConfigs++
		}
	}

	// 停止旧的后台刷新
	if as.tokenManager != nil {
		as.tokenManager.StopBackgroundRefresh()
	}

	// 重新创建TokenManager
	as.tokenManager = NewTokenManager(as.configs, as.tokensDir)

	// 重新启动后台刷新
	as.tokenManager.StartBackgroundRefresh()

	logger.Info("从tokens目录重新加载配置",
		logger.String("目录", tokensDir),
		logger.Int("新增配置", newConfigs),
		logger.Int("总配置数", len(as.configs)))

	return nil
}

// Shutdown 优雅关闭认证服务
// 停止后台刷新任务
func (as *AuthService) Shutdown() {
	logger.Info("正在关闭AuthService...")

	if as.tokenManager != nil {
		as.tokenManager.StopBackgroundRefresh()
		logger.Info("后台token刷新已停止")
	}

	logger.Info("AuthService已关闭")
}

// HealthStatus token池健康状态
type HealthStatus struct {
	Status          string `json:"status"`           // "healthy" 或 "degraded" 或 "unhealthy"
	TotalTokens     int    `json:"total_tokens"`     // 总token数
	AvailableTokens int    `json:"available_tokens"` // 可用token数
	LastRefreshTime string `json:"last_refresh_time"`// 最后刷新时间
}

// GetHealthStatus 获取token池健康状态
func (as *AuthService) GetHealthStatus() HealthStatus {
	if as.tokenManager == nil {
		return HealthStatus{
			Status:          "unhealthy",
			TotalTokens:     0,
			AvailableTokens: 0,
			LastRefreshTime: "never",
		}
	}

	totalTokens, availableTokens, lastRefresh := as.tokenManager.GetHealthInfo()

	status := "healthy"
	if availableTokens == 0 {
		status = "unhealthy"
	} else if availableTokens < totalTokens/2 {
		status = "degraded"
	}

	return HealthStatus{
		Status:          status,
		TotalTokens:     totalTokens,
		AvailableTokens: availableTokens,
		LastRefreshTime: lastRefresh.Format("2006-01-02 15:04:05"),
	}
}

// TODO: Token持久化功能将在后续版本中重新实现
// 由于循环依赖问题(auth -> dashboard -> auth)，暂时移除
// 计划：创建独立的storage包处理持久化，或在server层处理
