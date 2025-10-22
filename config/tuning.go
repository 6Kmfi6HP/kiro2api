package config

import "time"

// Tuning 性能和行为调优参数
// 从硬编码提取为可配置常量，遵循 KISS 原则
const (
	// ========== 解析器配置 ==========

	// ParserMaxErrors 解析器容忍的最大错误次数
	// 用于所有解析器，防止死循环
	ParserMaxErrors = 5

	// ========== Token缓存配置 ==========

	// TokenCacheTTL Token缓存的生存时间
	// 过期后需要重新刷新（已废弃，保留用于兼容性）
	TokenCacheTTL = 5 * time.Minute

	// ========== 后台刷新配置 ==========

	// BackgroundRefreshInterval 后台刷新检查间隔
	// 每60秒检查一次所有token的状态
	BackgroundRefreshInterval = 60 * time.Second

	// TokenRefreshWindow Token提前刷新窗口
	// 当token在10分钟内即将过期时触发刷新
	TokenRefreshWindow = 10 * time.Minute

	// MaxRefreshRetries 刷新失败最大重试次数
	MaxRefreshRetries = 3

	// RefreshRetryBaseDelay 刷新重试基础延迟
	// 使用指数退避：1s, 2s, 4s
	RefreshRetryBaseDelay = 1 * time.Second

	// ========== HTTP客户端配置 ==========

	// HTTPClientKeepAlive HTTP客户端Keep-Alive间隔
	HTTPClientKeepAlive = 30 * time.Second

	// HTTPClientTLSHandshakeTimeout HTTP客户端TLS握手超时
	HTTPClientTLSHandshakeTimeout = 15 * time.Second
)
