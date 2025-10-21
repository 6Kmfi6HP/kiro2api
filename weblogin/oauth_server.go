package weblogin

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"sync"
	"time"

	"kiro2api/logger"
)

// OAuthCallbackServer OAuth 回调服务器
type OAuthCallbackServer struct {
	server   *http.Server
	sessions sync.Map // map[sessionID]*LoginSession
	port     int
	hostname string
	mu       sync.Mutex
}

// NewOAuthCallbackServer 创建 OAuth 回调服务器
func NewOAuthCallbackServer(port int, hostname string) *OAuthCallbackServer {
	if hostname == "" {
		hostname = "127.0.0.1"
	}

	return &OAuthCallbackServer{
		port:     port,
		hostname: hostname,
	}
}

// Start 启动服务器
func (s *OAuthCallbackServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server != nil {
		return fmt.Errorf("server already started")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", s.handleCallback)

	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.hostname, s.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("OAuth callback server starting", logger.String("addr", s.server.Addr))
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("OAuth callback server error", logger.Err(err))
		}
	}()

	// 等待一小段时间确保服务器启动
	time.Sleep(100 * time.Millisecond)

	logger.Info("OAuth callback server started", logger.String("addr", s.server.Addr))
	return nil
}

// Stop 停止服务器
func (s *OAuthCallbackServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	s.server = nil
	logger.Info("OAuth callback server stopped")
	return nil
}

// GetRedirectURI 获取回调 URI
func (s *OAuthCallbackServer) GetRedirectURI() string {
	return fmt.Sprintf("http://%s:%d/oauth/callback", s.hostname, s.port)
}

// RegisterSession 注册登录会话
func (s *OAuthCallbackServer) RegisterSession(session *LoginSession) {
	s.sessions.Store(session.State, session)
	logger.Debug("Registered login session", logger.String("sessionId", session.SessionID), logger.String("state", session.State))
}

// UnregisterSession 取消注册登录会话
func (s *OAuthCallbackServer) UnregisterSession(state string) {
	s.sessions.Delete(state)
	logger.Debug("Unregistered login session", logger.String("state", state))
}

// handleCallback 处理 OAuth 回调
func (s *OAuthCallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	logger.Info("Received OAuth callback", logger.String("method", r.Method), logger.String("url", r.URL.String()))

	// 解析查询参数
	query := r.URL.Query()

	// 检查错误
	if errCode := query.Get("error"); errCode != "" {
		errDesc := query.Get("error_description")
		if errDesc == "" {
			errDesc = "Unknown error"
		}

		logger.Error("OAuth callback error", logger.String("error", errCode), logger.String("description", errDesc))
		s.sendErrorResponse(w, errCode, errDesc)

		// 通知会话
		if state := query.Get("state"); state != "" {
			if session, ok := s.sessions.Load(state); ok {
				sess := session.(*LoginSession)
				select {
				case sess.ErrorChan <- fmt.Errorf("OAuth error: %s - %s", errCode, errDesc):
				default:
				}
				s.UnregisterSession(state)
			}
		}
		return
	}

	// 获取授权码和 state
	code := query.Get("code")
	state := query.Get("state")

	if code == "" || state == "" {
		logger.Error("Missing code or state parameter")
		s.sendErrorResponse(w, "invalid_request", "Missing code or state parameter")
		return
	}

	logger.Info("OAuth callback success", logger.String("code", code[:20]+"..."), logger.String("state", state))

	// 查找会话
	sessionVal, ok := s.sessions.Load(state)
	if !ok {
		logger.Error("Session not found", logger.String("state", state))
		s.sendErrorResponse(w, "invalid_state", "Session not found or expired")
		return
	}

	session := sessionVal.(*LoginSession)

	// 发送成功响应给浏览器
	s.sendSuccessResponse(w)

	// 在后台处理 token 交换
	go s.handleTokenExchange(session, code)
}

// handleTokenExchange 处理 token 交换
func (s *OAuthCallbackServer) handleTokenExchange(session *LoginSession, code string) {
	defer s.UnregisterSession(session.State)

	logger.Debug("Exchanging authorization code for token", logger.String("sessionId", session.SessionID))

	// 创建 Kiro Auth 客户端
	authClient := NewKiroAuthClient()

	// 交换授权码
	tokenResp, err := authClient.CreateToken(code, session.CodeVerifier, session.RedirectURI)
	if err != nil {
		logger.Error("Failed to exchange token", logger.String("sessionId", session.SessionID), logger.Err(err))
		select {
		case session.ErrorChan <- err:
		default:
		}
		return
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

	logger.Info("Token exchange successful", logger.String("sessionId", session.SessionID), logger.String("profileArn", tokenResp.ProfileArn))

	// 发送结果
	select {
	case session.ResultChan <- tokenData:
	default:
	}
}

// sendSuccessResponse 发送成功响应
func (s *OAuthCallbackServer) sendSuccessResponse(w http.ResponseWriter) {
	htmlContent := `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Authentication Successful</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .container {
      background: white;
      padding: 3rem;
      border-radius: 1rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 400px;
    }
    .success-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
    }
    h1 {
      color: #2d3748;
      margin: 0 0 1rem 0;
      font-size: 1.5rem;
    }
    p {
      color: #718096;
      margin: 0;
      line-height: 1.6;
    }
    .close-hint {
      margin-top: 1.5rem;
      padding-top: 1.5rem;
      border-top: 1px solid #e2e8f0;
      font-size: 0.875rem;
      color: #a0aec0;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">✅</div>
    <h1>Authentication Successful!</h1>
    <p>You have successfully authenticated.</p>
    <p>You can now close this window and return to the control panel.</p>
    <div class="close-hint">This window will close automatically in 3 seconds...</div>
  </div>
  <script>
    setTimeout(() => window.close(), 3000);
  </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(htmlContent))
}

// sendErrorResponse 发送错误响应
func (s *OAuthCallbackServer) sendErrorResponse(w http.ResponseWriter, errCode, errDesc string) {
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Authentication Failed</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
    }
    .container {
      background: white;
      padding: 3rem;
      border-radius: 1rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 400px;
    }
    .error-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
    }
    h1 {
      color: #2d3748;
      margin: 0 0 1rem 0;
      font-size: 1.5rem;
    }
    .error-details {
      background: #fff5f5;
      border: 1px solid #feb2b2;
      border-radius: 0.5rem;
      padding: 1rem;
      margin: 1rem 0;
      text-align: left;
    }
    .error-code {
      font-family: monospace;
      color: #c53030;
      font-weight: bold;
    }
    .error-description {
      color: #718096;
      margin-top: 0.5rem;
      font-size: 0.875rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-icon">❌</div>
    <h1>Authentication Failed</h1>
    <div class="error-details">
      <div class="error-code">%s</div>
      <div class="error-description">%s</div>
    </div>
    <p>Please try again or contact support if the problem persists.</p>
  </div>
</body>
</html>`, html.EscapeString(errCode), html.EscapeString(errDesc))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(htmlContent))
}
