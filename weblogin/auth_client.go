package weblogin

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"kiro2api/logger"
)

const (
	// Kiro Auth Service endpoint
	kiroAuthEndpoint = "https://prod.us-east-1.auth.desktop.kiro.dev"
)

// KiroAuthClient Kiro 认证服务客户端
type KiroAuthClient struct {
	httpClient *http.Client
}

// NewKiroAuthClient 创建 Kiro 认证服务客户端
func NewKiroAuthClient() *KiroAuthClient {
	return &KiroAuthClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateTokenRequest Token 创建请求
type CreateTokenRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	InvitationCode string `json:"invitation_code,omitempty"`
}

// CreateTokenResponse Token 创建响应
type CreateTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
	ProfileArn   string `json:"profileArn"`
	IDToken      string `json:"idToken,omitempty"`
}

// RefreshTokenRequest Token 刷新请求
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// RefreshTokenResponse Token 刷新响应
type RefreshTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
}

// GetLoginURL 获取登录 URL
func (c *KiroAuthClient) GetLoginURL(provider LoginProvider, redirectURI, codeChallenge, state string) string {
	return fmt.Sprintf("%s/login?idp=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s",
		kiroAuthEndpoint,
		provider,
		redirectURI,
		codeChallenge,
		state,
	)
}

// CreateToken 交换授权码为访问令牌
func (c *KiroAuthClient) CreateToken(code, codeVerifier, redirectURI string) (*CreateTokenResponse, error) {
	req := CreateTokenRequest{
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  redirectURI,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/oauth/token", kiroAuthEndpoint)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "kiro2api/1.0.0")

	logger.Debug("Creating token", "url", url)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token creation failed: %d - %s", resp.StatusCode, string(body))
	}

	var tokenResp CreateTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &tokenResp, nil
}

// RefreshToken 刷新访问令牌
func (c *KiroAuthClient) RefreshToken(refreshToken string) (*RefreshTokenResponse, error) {
	req := RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/refreshToken", kiroAuthEndpoint)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "kiro2api/1.0.0")

	logger.Debug("Refreshing token", "url", url)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: %d - %s", resp.StatusCode, string(body))
	}

	var refreshResp RefreshTokenResponse
	if err := json.Unmarshal(body, &refreshResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &refreshResp, nil
}

// GeneratePKCE 生成 PKCE 参数
func GeneratePKCE() (verifier, challenge string, err error) {
	// 生成 code verifier (43-128 个字符)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// 生成 code challenge (SHA256 hash of verifier)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}

// GenerateState 生成随机 state 参数
func GenerateState() (string, error) {
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(stateBytes), nil
}
