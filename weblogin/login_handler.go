package weblogin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"kiro2api/logger"
)

// LoginHandler 登录处理器
type LoginHandler struct {
	oauthServer  *OAuthCallbackServer
	authClient   *KiroAuthClient
	tokenManager *TokenManager
	sessions     sync.Map // map[sessionID]*LoginSession
}

// NewLoginHandler 创建登录处理器
func NewLoginHandler(oauthServer *OAuthCallbackServer, tokenManager *TokenManager) *LoginHandler {
	return &LoginHandler{
		oauthServer:  oauthServer,
		authClient:   NewKiroAuthClient(),
		tokenManager: tokenManager,
	}
}

// StartLogin 启动登录流程
func (h *LoginHandler) StartLogin(req *LoginRequest) (*LoginResponse, error) {
	// 验证请求
	if req.Provider == "" {
		return nil, fmt.Errorf("provider is required")
	}

	// 生成 PKCE 参数
	codeVerifier, codeChallenge, err := GeneratePKCE()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// 生成 state 参数
	state, err := GenerateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// 生成会话 ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// 获取 redirect URI
	redirectURI := h.oauthServer.GetRedirectURI()

	// 创建登录会话
	session := &LoginSession{
		SessionID:     sessionID,
		Provider:      req.Provider,
		Region:        req.Region,
		StartURL:      req.StartURL,
		AccountName:   req.AccountName,
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		State:         state,
		RedirectURI:   redirectURI,
		CreatedAt:     time.Now(),
		ResultChan:    make(chan *TokenData, 1),
		ErrorChan:     make(chan error, 1),
	}

	// 保存会话
	h.sessions.Store(sessionID, session)
	h.oauthServer.RegisterSession(session)

	// 生成授权 URL
	authURL := h.authClient.GetLoginURL(req.Provider, redirectURI, codeChallenge, state)

	logger.Info("Login session started", "sessionId", sessionID, "provider", req.Provider)

	return &LoginResponse{
		SessionID:    sessionID,
		AuthURL:      authURL,
		RedirectURI:  redirectURI,
		Message:      "Please open the auth URL in your browser to complete login",
		IsLocalhost:  h.oauthServer.hostname == "127.0.0.1" || h.oauthServer.hostname == "localhost",
	}, nil
}

// WaitForLogin 等待登录完成
func (h *LoginHandler) WaitForLogin(sessionID string, timeout time.Duration) (*TokenData, error) {
	sessionVal, ok := h.sessions.Load(sessionID)
	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	session := sessionVal.(*LoginSession)

	// 设置超时
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case tokenData := <-session.ResultChan:
		// 保存 token
		filename, err := h.tokenManager.SaveToken(tokenData)
		if err != nil {
			logger.Error("Failed to save token", "sessionId", sessionID, "error", err)
			return nil, fmt.Errorf("failed to save token: %w", err)
		}

		logger.Info("Login completed successfully", "sessionId", sessionID, "filename", filename)
		h.sessions.Delete(sessionID)
		return tokenData, nil

	case err := <-session.ErrorChan:
		logger.Error("Login failed", "sessionId", sessionID, "error", err)
		h.sessions.Delete(sessionID)
		return nil, err

	case <-timer.C:
		logger.Error("Login timeout", "sessionId", sessionID)
		h.sessions.Delete(sessionID)
		h.oauthServer.UnregisterSession(session.State)
		return nil, fmt.Errorf("login timeout")
	}
}

// HandleManualCallback 处理手动回调
func (h *LoginHandler) HandleManualCallback(req *ManualCallbackRequest) (*TokenData, error) {
	// 解析回调 URL
	// 格式: http://127.0.0.1:8081/oauth/callback?code=xxx&state=xxx
	// 这里需要从 URL 中提取 code 和 state

	sessionVal, ok := h.sessions.Load(req.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	session := sessionVal.(*LoginSession)

	// 解析回调 URL
	code, state, err := parseCallbackURL(req.CallbackURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse callback URL: %w", err)
	}

	// 验证 state
	if state != session.State {
		return nil, fmt.Errorf("invalid state parameter")
	}

	logger.Debug("Processing manual callback", "sessionId", req.SessionID, "code", code[:20]+"...")

	// 交换授权码
	tokenResp, err := h.authClient.CreateToken(code, session.CodeVerifier, session.RedirectURI)
	if err != nil {
		logger.Error("Failed to exchange token", "sessionId", req.SessionID, "error", err)
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	// 构造 TokenData
	tokenData := &TokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Provider:     session.Provider,
		AuthMethod:   AuthMethodSocial,
		AccountName:  session.AccountName,
		ProfileArn:   tokenResp.ProfileArn,
		IDToken:      tokenResp.IDToken,
		CreatedAt:    time.Now(),
	}

	// 保存 token
	filename, err := h.tokenManager.SaveToken(tokenData)
	if err != nil {
		logger.Error("Failed to save token", "sessionId", req.SessionID, "error", err)
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	logger.Info("Manual callback processed successfully", "sessionId", req.SessionID, "filename", filename)

	// 清理会话
	h.sessions.Delete(req.SessionID)
	h.oauthServer.UnregisterSession(session.State)

	return tokenData, nil
}

// ListTokens 列出所有 token
func (h *LoginHandler) ListTokens() ([]*TokenListItem, error) {
	return h.tokenManager.ListTokens()
}

// DeleteToken 删除 token
func (h *LoginHandler) DeleteToken(filename string) error {
	return h.tokenManager.DeleteToken(filename)
}

// RefreshToken 刷新 token
func (h *LoginHandler) RefreshToken(filename string) (*TokenData, error) {
	// 加载旧 token
	oldToken, err := h.tokenManager.LoadToken(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to load token: %w", err)
	}

	// 刷新 token
	refreshResp, err := h.authClient.RefreshToken(oldToken.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// 更新 token 数据
	now := time.Now()
	oldToken.AccessToken = refreshResp.AccessToken
	oldToken.RefreshToken = refreshResp.RefreshToken
	oldToken.TokenType = refreshResp.TokenType
	oldToken.ExpiresIn = refreshResp.ExpiresIn
	oldToken.ExpiresAt = now.Add(time.Duration(refreshResp.ExpiresIn) * time.Second)
	oldToken.RefreshedAt = &now

	// 保存更新后的 token
	if _, err := h.tokenManager.SaveToken(oldToken); err != nil {
		return nil, fmt.Errorf("failed to save refreshed token: %w", err)
	}

	logger.Info("Token refreshed successfully", "filename", filename)
	return oldToken, nil
}

// generateSessionID 生成会话 ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// parseCallbackURL 解析回调 URL
func parseCallbackURL(callbackURL string) (code, state string, err error) {
	// 简单解析 URL 查询参数
	// 格式: http://127.0.0.1:8081/oauth/callback?code=xxx&state=xxx

	// 这里可以使用更健壮的 URL 解析
	// 为了简单起见，我们使用简单的字符串操作

	// 找到 ? 后面的查询参数
	idx := 0
	for i, c := range callbackURL {
		if c == '?' {
			idx = i + 1
			break
		}
	}

	if idx == 0 {
		return "", "", fmt.Errorf("invalid callback URL: missing query parameters")
	}

	query := callbackURL[idx:]

	// 解析查询参数
	params := make(map[string]string)
	pairs := splitString(query, '&')
	for _, pair := range pairs {
		kv := splitString(pair, '=')
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		}
	}

	code = params["code"]
	state = params["state"]

	if code == "" || state == "" {
		return "", "", fmt.Errorf("invalid callback URL: missing code or state parameter")
	}

	return code, state, nil
}

// splitString 分割字符串
func splitString(s string, sep rune) []string {
	var result []string
	var current string

	for _, c := range s {
		if c == sep {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}

	if current != "" {
		result = append(result, current)
	}

	return result
}
