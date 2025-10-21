package weblogin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kiro2api/logger"
)

// TokenManager Token 管理器
type TokenManager struct {
	tokenDir string
}

// NewTokenManager 创建 Token 管理器
func NewTokenManager(tokenDir string) (*TokenManager, error) {
	// 确保 token 目录存在
	if err := os.MkdirAll(tokenDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create token directory: %w", err)
	}

	return &TokenManager{
		tokenDir: tokenDir,
	}, nil
}

// SaveToken 保存 token 到文件
func (tm *TokenManager) SaveToken(tokenData *TokenData) (string, error) {
	// 生成文件名
	filename := tm.generateTokenFilename(tokenData)
	filepath := filepath.Join(tm.tokenDir, filename)

	// 设置元数据
	tokenData.SavedAt = time.Now()
	tokenData.Version = "1.0"

	// 保存到文件
	data, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal token data: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write token file: %w", err)
	}

	logger.Info("Token saved", logger.String("filename", filename), logger.String("provider", string(tokenData.Provider)), logger.String("authMethod", string(tokenData.AuthMethod)))
	return filename, nil
}

// LoadToken 从文件加载 token
func (tm *TokenManager) LoadToken(filename string) (*TokenData, error) {
	filepath := filepath.Join(tm.tokenDir, filename)

	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var tokenData TokenData
	if err := json.Unmarshal(data, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token data: %w", err)
	}

	return &tokenData, nil
}

// ListTokens 列出所有 token
func (tm *TokenManager) ListTokens() ([]*TokenListItem, error) {
	entries, err := os.ReadDir(tm.tokenDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read token directory: %w", err)
	}

	var tokens []*TokenListItem
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		tokenData, err := tm.LoadToken(entry.Name())
		if err != nil {
			logger.Warn("Failed to load token", logger.String("filename", entry.Name()), logger.Err(err))
			continue
		}

		tokens = append(tokens, &TokenListItem{
			ID:          tm.generateTokenID(entry.Name()),
			Filename:    entry.Name(),
			Provider:    tokenData.Provider,
			AuthMethod:  tokenData.AuthMethod,
			AccountName: tokenData.AccountName,
			CreatedAt:   tokenData.CreatedAt,
			ExpiresAt:   tokenData.ExpiresAt,
			IsExpired:   time.Now().After(tokenData.ExpiresAt),
			Status:      tm.getTokenStatus(tokenData),
		})
	}

	// 按创建时间排序（最新的在前）
	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].CreatedAt.After(tokens[j].CreatedAt)
	})

	return tokens, nil
}

// DeleteToken 删除 token
func (tm *TokenManager) DeleteToken(filename string) error {
	filepath := filepath.Join(tm.tokenDir, filename)

	if err := os.Remove(filepath); err != nil {
		return fmt.Errorf("failed to delete token file: %w", err)
	}

	logger.Info("Token deleted", logger.String("filename", filename))
	return nil
}

// LoadAllTokens 加载所有有效的 token
func (tm *TokenManager) LoadAllTokens() ([]*TokenData, error) {
	entries, err := os.ReadDir(tm.tokenDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read token directory: %w", err)
	}

	var tokens []*TokenData
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		tokenData, err := tm.LoadToken(entry.Name())
		if err != nil {
			logger.Warn("Failed to load token", logger.String("filename", entry.Name()), logger.Err(err))
			continue
		}

		// 跳过已过期的 token
		if time.Now().After(tokenData.ExpiresAt) {
			logger.Debug("Skipping expired token", logger.String("filename", entry.Name()))
			continue
		}

		tokens = append(tokens, tokenData)
	}

	return tokens, nil
}

// generateTokenFilename 生成 token 文件名
func (tm *TokenManager) generateTokenFilename(tokenData *TokenData) string {
	timestamp := time.Now().Unix()
	provider := string(tokenData.Provider)
	authMethod := string(tokenData.AuthMethod)
	accountName := tokenData.AccountName
	if accountName == "" {
		accountName = fmt.Sprintf("account_%d", timestamp)
	}

	// 清理账户名
	accountName = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, accountName)

	return fmt.Sprintf("token-%s-%s-%s-%d.json",
		strings.ToLower(provider),
		strings.ToLower(authMethod),
		strings.ToLower(accountName),
		timestamp)
}

// generateTokenID 生成 token ID
func (tm *TokenManager) generateTokenID(filename string) string {
	hash := sha256.Sum256([]byte(filename))
	return hex.EncodeToString(hash[:])[:16]
}

// getTokenStatus 获取 token 状态
func (tm *TokenManager) getTokenStatus(tokenData *TokenData) string {
	now := time.Now()
	if now.After(tokenData.ExpiresAt) {
		return "expired"
	}

	timeToExpire := tokenData.ExpiresAt.Sub(now)
	if timeToExpire < 5*time.Minute {
		return "expiring"
	}

	return "valid"
}

// IsTokenExpired 检查 token 是否过期
func IsTokenExpired(tokenData *TokenData) bool {
	return time.Now().After(tokenData.ExpiresAt)
}
