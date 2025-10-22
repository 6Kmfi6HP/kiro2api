package auth

import (
	"fmt"
	"kiro2api/logger"
	"kiro2api/types"
)

// AuthService 认证服务（推荐使用依赖注入方式）
type AuthService struct {
	tokenManager *TokenManager
	configs      []AuthConfig
}

// NewAuthService 创建新的认证服务（推荐使用此方法而不是全局函数）
func NewAuthService() (*AuthService, error) {
	logger.Info("创建AuthService实例")

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

	// 创建token管理器
	tokenManager := NewTokenManager(configs)

	// 仅在有配置时预热token
	if len(configs) > 0 {
		_, warmupErr := tokenManager.getBestToken()
		if warmupErr != nil {
			logger.Warn("token预热失败", logger.Err(warmupErr))
		}
	}

	logger.Info("AuthService创建完成", logger.Int("config_count", len(configs)))

	return &AuthService{
		tokenManager: tokenManager,
		configs:      configs,
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

	// 重新创建TokenManager以包含新配置
	as.tokenManager = NewTokenManager(as.configs)

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

	// 重新创建TokenManager
	as.tokenManager = NewTokenManager(as.configs)

	logger.Info("从tokens目录重新加载配置",
		logger.String("目录", tokensDir),
		logger.Int("新增配置", newConfigs),
		logger.Int("总配置数", len(as.configs)))

	return nil
}
