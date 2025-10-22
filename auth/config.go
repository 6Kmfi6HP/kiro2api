package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kiro2api/logger"
)

// AuthConfig 简化的认证配置
type AuthConfig struct {
	AuthType     string `json:"auth"`
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	Disabled     bool   `json:"disabled,omitempty"`
}

// 认证方法常量
const (
	AuthMethodSocial = "Social"
	AuthMethodIdC    = "IdC"
)

// loadConfigs 从环境变量或文件目录加载配置
func loadConfigs() ([]AuthConfig, error) {
	// 检测并警告弃用的环境变量
	deprecatedVars := []string{
		"REFRESH_TOKEN",
		"AWS_REFRESHTOKEN",
		"IDC_REFRESH_TOKEN",
		"BULK_REFRESH_TOKENS",
	}

	for _, envVar := range deprecatedVars {
		if os.Getenv(envVar) != "" {
			logger.Warn("检测到已弃用的环境变量",
				logger.String("变量名", envVar),
				logger.String("迁移说明", "请迁移到KIRO_AUTH_TOKEN的JSON格式"))
			logger.Warn("迁移示例",
				logger.String("新格式", `KIRO_AUTH_TOKEN='[{"auth":"Social","refreshToken":"your_token"}]'`))
		}
	}

	var allConfigs []AuthConfig

	// 1. 尝试从KIRO_AUTH_TOKEN环境变量加载（优先级最高）
	jsonData := os.Getenv("KIRO_AUTH_TOKEN")
	if jsonData != "" {
		// 优先尝试从文件加载，失败后再作为JSON字符串处理
		var configData string
		if fileInfo, err := os.Stat(jsonData); err == nil && !fileInfo.IsDir() {
			// 是文件，读取文件内容
			content, err := os.ReadFile(jsonData)
			if err != nil {
				return nil, fmt.Errorf("读取配置文件失败: %w\n配置文件路径: %s", err, jsonData)
			}
			configData = string(content)
			logger.Info("从文件加载认证配置", logger.String("文件路径", jsonData))
		} else {
			// 不是文件或文件不存在，作为JSON字符串处理
			configData = jsonData
			logger.Debug("从环境变量加载JSON配置")
		}

		// 解析JSON配置
		configs, err := parseJSONConfig(configData)
		if err != nil {
			return nil, fmt.Errorf("解析KIRO_AUTH_TOKEN失败: %w\n"+
				"请检查JSON格式是否正确\n"+
				"示例: KIRO_AUTH_TOKEN='[{\"auth\":\"Social\",\"refreshToken\":\"token1\"}]'", err)
		}

		allConfigs = append(allConfigs, configs...)
		logger.Info("从环境变量加载配置",
			logger.Int("配置数", len(configs)))
	} else {
		// 2. 仅在KIRO_AUTH_TOKEN未设置时从tokens/目录加载配置
		tokensDir := os.Getenv("KIRO_TOKENS_DIR")
		if tokensDir == "" {
			tokensDir = "tokens"
		}

		fileConfigs, err := LoadTokensFromDirectory(tokensDir)
		if err != nil {
			logger.Warn("从tokens目录加载配置失败",
				logger.String("目录", tokensDir),
				logger.Err(err))
		} else if len(fileConfigs) > 0 {
			allConfigs = append(allConfigs, fileConfigs...)
			logger.Info("从tokens目录加载配置",
				logger.String("目录", tokensDir),
				logger.Int("配置数", len(fileConfigs)))
		}
	}

	// 如果没有任何配置，返回空列表（不再是错误）
	if len(allConfigs) == 0 {
		logger.Warn("未找到任何认证配置",
			logger.String("提示", "可以通过KIRO_AUTH_TOKEN环境变量或tokens/目录提供配置"))
		return []AuthConfig{}, nil
	}

	validConfigs := processConfigs(allConfigs)
	if len(validConfigs) == 0 {
		logger.Warn("没有有效的认证配置",
			logger.String("提示", "请检查配置格式是否正确"))
		return []AuthConfig{}, nil
	}

	logger.Info("成功加载认证配置",
		logger.Int("总配置数", len(allConfigs)),
		logger.Int("有效配置数", len(validConfigs)))

	return validConfigs, nil
}

// GetConfigs 公开的配置获取函数，供其他包调用
func GetConfigs() ([]AuthConfig, error) {
	return loadConfigs()
}

// parseJSONConfig 解析JSON配置字符串
func parseJSONConfig(jsonData string) ([]AuthConfig, error) {
	var configs []AuthConfig

	// 尝试解析为数组
	if err := json.Unmarshal([]byte(jsonData), &configs); err != nil {
		// 尝试解析为单个对象
		var single AuthConfig
		if err := json.Unmarshal([]byte(jsonData), &single); err != nil {
			return nil, fmt.Errorf("JSON格式无效: %w", err)
		}
		configs = []AuthConfig{single}
	}

	return configs, nil
}

// processConfigs 处理和验证配置
func processConfigs(configs []AuthConfig) []AuthConfig {
	var validConfigs []AuthConfig

	for i, config := range configs {
		// 验证必要字段
		if config.RefreshToken == "" {
			continue
		}

		// 设置默认认证类型
		if config.AuthType == "" {
			config.AuthType = AuthMethodSocial
		}

		// 验证IdC认证的必要字段
		if config.AuthType == AuthMethodIdC {
			if config.ClientID == "" || config.ClientSecret == "" {
				continue
			}
		}

		// 跳过禁用的配置
		if config.Disabled {
			continue
		}

		validConfigs = append(validConfigs, config)
		_ = i // 避免未使用变量警告
	}

	return validConfigs
}

// LoadTokensFromDirectory 从指定目录加载token配置文件
func LoadTokensFromDirectory(tokensDir string) ([]AuthConfig, error) {
	// 检查目录是否存在
	if _, err := os.Stat(tokensDir); os.IsNotExist(err) {
		logger.Debug("Tokens目录不存在", logger.String("目录", tokensDir))
		return []AuthConfig{}, nil
	}

	// 读取目录中的所有文件
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		return nil, fmt.Errorf("读取tokens目录失败: %w", err)
	}

	var configs []AuthConfig
	var loadErrors []string

	for _, entry := range entries {
		// 跳过目录和非JSON文件
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// 跳过临时文件
		if filepath.Ext(entry.Name()) == ".tmp" {
			continue
		}

		filePath := filepath.Join(tokensDir, entry.Name())

		// 读取并解析token文件
		config, err := loadTokenConfigFile(filePath)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", entry.Name(), err))
			logger.Warn("加载token配置文件失败",
				logger.String("文件", entry.Name()),
				logger.Err(err))
			continue
		}

		configs = append(configs, config)
	}

	if len(loadErrors) > 0 {
		logger.Warn("部分token配置文件加载失败",
			logger.Any("错误", loadErrors))
	}

	return configs, nil
}

// loadTokenConfigFile 从文件加载单个token配置
func loadTokenConfigFile(filePath string) (AuthConfig, error) {
	// 读取文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		return AuthConfig{}, fmt.Errorf("读取文件失败: %w", err)
	}

	// 解析JSON - 支持两种格式：
	// 1. dashboard.StoredToken格式（包含id, authMethod等字段）
	// 2. 直接的AuthConfig格式
	var tokenData map[string]interface{}
	if err := json.Unmarshal(data, &tokenData); err != nil {
		return AuthConfig{}, fmt.Errorf("解析JSON失败: %w", err)
	}

	// 构建AuthConfig
	config := AuthConfig{}

	// 尝试从不同的字段名获取认证类型
	if authMethod, ok := tokenData["authMethod"].(string); ok {
		config.AuthType = authMethod
	} else if auth, ok := tokenData["auth"].(string); ok {
		config.AuthType = auth
	}

	// 获取refreshToken
	if refreshToken, ok := tokenData["refreshToken"].(string); ok {
		config.RefreshToken = refreshToken
	}

	// 获取clientId和clientSecret（IdC认证需要）
	if clientId, ok := tokenData["clientId"].(string); ok {
		config.ClientID = clientId
	}
	if clientSecret, ok := tokenData["clientSecret"].(string); ok {
		config.ClientSecret = clientSecret
	}

	// 检查disabled字段
	if disabled, ok := tokenData["disabled"].(bool); ok {
		config.Disabled = disabled
	}

	// 验证必要字段
	if config.RefreshToken == "" {
		return AuthConfig{}, fmt.Errorf("refreshToken字段为空")
	}

	// 设置默认认证类型
	if config.AuthType == "" {
		config.AuthType = AuthMethodSocial
	}

	// 验证IdC认证的必要字段
	if config.AuthType == AuthMethodIdC {
		if config.ClientID == "" || config.ClientSecret == "" {
			return AuthConfig{}, fmt.Errorf("IdC认证缺少clientId或clientSecret")
		}
	}

	return config, nil
}
