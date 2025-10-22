package dashboard

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"sync"
	"time"

	"kiro2api/auth"
	"kiro2api/logger"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// DashboardHandler handles dashboard HTTP requests
type DashboardHandler struct {
	stateStore       *StateStore
	tokensDir        string
	kiroClient       *KiroAuthClient
	authService      *auth.AuthService
	templates        *template.Template
	activeServers    map[string]*CallbackServer
	activeServersMux sync.Mutex
}

// NewDashboardHandler creates a new dashboard handler
func NewDashboardHandler(tokensDir string, authService *auth.AuthService) (*DashboardHandler, error) {
	if tokensDir == "" {
		tokensDir = DefaultTokensDir
	}

	// Validate tokens directory
	if err := ValidateTokensDirectory(tokensDir); err != nil {
		return nil, fmt.Errorf("failed to validate tokens directory: %w", err)
	}

	// Load templates from embedded filesystem
	templates, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		logger.Warn("Failed to load dashboard templates", logger.Err(err))
		// Continue without templates - will use JSON responses
	}

	return &DashboardHandler{
		stateStore:    NewStateStore(),
		tokensDir:     tokensDir,
		kiroClient:    NewKiroAuthClient(),
		authService:   authService,
		templates:     templates,
		activeServers: make(map[string]*CallbackServer),
	}, nil
}

// Home renders the dashboard home page
// GET /dashboard
func (h *DashboardHandler) Home(c *gin.Context) {
	// Load all tokens
	tokens, err := LoadTokens(h.tokensDir)
	if err != nil {
		logger.Error("Failed to load tokens", logger.Err(err))
		RenderError(c, http.StatusInternalServerError, "Failed to load tokens")
		return
	}

	// Calculate token status
	type TokenDisplay struct {
		ID         string
		Provider   string
		AuthMethod string
		Status     string
		ExpiresAt  string
		CreatedAt  string
	}

	displayTokens := make([]TokenDisplay, 0, len(tokens))
	for _, token := range tokens {
		status := "valid"
		if !token.ExpiresAt.IsZero() {
			timeUntilExpiry := time.Until(token.ExpiresAt)
			if timeUntilExpiry < 0 {
				status = "expired"
			} else if timeUntilExpiry < 24*time.Hour {
				status = "expiring"
			}
		}

		displayTokens = append(displayTokens, TokenDisplay{
			ID:         token.ID,
			Provider:   token.Provider,
			AuthMethod: token.AuthMethod,
			Status:     status,
			ExpiresAt:  token.ExpiresAt.Format(time.RFC3339),
			CreatedAt:  token.CreatedAt.Format(time.RFC3339),
		})
	}

	data := gin.H{
		"tokens":    displayTokens,
		"providers": ListProviders(),
	}

	// Try to render template, fallback to JSON
	if h.templates != nil {
		if err := h.templates.ExecuteTemplate(c.Writer, "index.html", data); err != nil {
			logger.Error("Failed to render template", logger.Err(err))
			JSONSuccess(c, data)
		}
	} else {
		JSONSuccess(c, data)
	}
}

// Login initiates OAuth flow (API endpoint)
// GET /dashboard/api/login?provider=BuilderId&startUrl=https://...
func (h *DashboardHandler) Login(c *gin.Context) {
	provider := c.Query("provider")
	startURL := c.Query("startUrl")

	// Validate provider
	providerConfig, err := GetProvider(provider)
	if err != nil {
		logger.Error("Invalid provider", logger.String("provider", provider), logger.Err(err))
		JSONError(c, http.StatusBadRequest, fmt.Sprintf("Invalid provider: %s", provider))
		return
	}

	// Generate PKCE parameters
	pkce, err := GeneratePKCE()
	if err != nil {
		logger.Error("Failed to generate PKCE", logger.Err(err))
		JSONError(c, http.StatusInternalServerError, "Failed to generate PKCE parameters")
		return
	}

	// Generate state
	state := GenerateState()

	// Determine callback strategy
	var callbackServer *CallbackServer
	var redirectURI string

	if providerConfig.AuthMethod == "IdC" {
		// IdC: Use random port with 127.0.0.1
		callbackServer = NewCallbackServer(CallbackServerOptions{
			Strategy: "random",
			Hostname: "127.0.0.1",
			Timeout:  5 * time.Minute,
		})
	} else {
		// Social: Use predefined ports with localhost (required by Kiro Auth Service)
		callbackServer = NewCallbackServer(CallbackServerOptions{
			Strategy: "predefined",
			Ports:    providerConfig.RedirectPorts,
			Hostname: "localhost", // IMPORTANT: Must use "localhost" for Social auth
			Timeout:  5 * time.Minute,
		})
	}

	// Start callback server
	redirectURI, err = callbackServer.Start()
	if err != nil {
		logger.Error("Failed to start callback server", logger.Err(err))
		JSONError(c, http.StatusInternalServerError, "Failed to start callback server")
		return
	}

	logger.Info("Callback server started",
		logger.String("redirect_uri", redirectURI),
		logger.String("provider", provider))

	// Store server instance for cancellation
	h.activeServersMux.Lock()
	h.activeServers[state] = callbackServer
	h.activeServersMux.Unlock()

	// Save state
	oauthState := &OAuthState{
		State:         state,
		CodeVerifier:  pkce.CodeVerifier,
		CodeChallenge: pkce.CodeChallenge,
		Provider:      provider,
		StartURL:      startURL,
		RedirectURI:   redirectURI, // Store redirect URI for token exchange
	}

	if err := h.stateStore.SaveState(state, oauthState); err != nil {
		logger.Error("Failed to save state", logger.Err(err))
		callbackServer.Stop()
		JSONError(c, http.StatusInternalServerError, "Failed to save OAuth state")
		return
	}

	// Build authorization URL based on auth method
	var authURL string
	var clientID, clientSecret string

	if providerConfig.AuthMethod == "IdC" {
		// IdC: Use AWS SSO OIDC with dynamic client registration
		logger.Info("Starting IdC authentication flow", logger.String("provider", provider))

		// Create AWS SSO client
		region := c.DefaultQuery("region", "us-east-1")
		ssoClient := NewAWSSSOClient(region)

		// Get start URL
		startURL := ssoClient.GetStartURL(provider, startURL)
		logger.Info("Using start URL", logger.String("url", startURL))

		// Register OAuth client
		clientReg, err := ssoClient.RegisterClient(startURL)
		if err != nil {
			logger.Error("Failed to register OAuth client", logger.Err(err))
			callbackServer.Stop()
			JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to register OAuth client: %v", err))
			return
		}

		clientID = clientReg.ClientID
		clientSecret = clientReg.ClientSecret

		// Build authorization URL
		authURL, err = ssoClient.BuildAuthorizationURL(AuthorizationURLParams{
			ClientID:      clientReg.ClientID,
			RedirectURI:   redirectURI,
			CodeChallenge: pkce.CodeChallenge,
			State:         state,
			Scopes:        providerConfig.Scopes,
		})
		if err != nil {
			logger.Error("Failed to build authorization URL", logger.Err(err))
			callbackServer.Stop()
			JSONError(c, http.StatusInternalServerError, "Failed to build authorization URL")
			return
		}

		// Store client credentials in state for token exchange
		oauthState.ClientID = clientID
		oauthState.ClientSecret = clientSecret
		oauthState.Region = region

		logger.Info("IdC OAuth client registered",
			logger.String("client_id", clientID[:20]+"..."),
			logger.String("region", region))
	} else {
		// Social: Use Kiro auth service
		authURL, err = h.kiroClient.GetLoginURL(LoginParams{
			Provider:      provider,
			RedirectURI:   redirectURI,
			CodeChallenge: pkce.CodeChallenge,
			State:         state,
		})
		if err != nil {
			logger.Error("Failed to build authorization URL", logger.Err(err))
			callbackServer.Stop()
			JSONError(c, http.StatusInternalServerError, "Failed to build authorization URL")
			return
		}
	}

	// Start goroutine to wait for callback
	go h.waitForCallback(callbackServer, state)

	// Return authorization URL
	JSONSuccess(c, gin.H{
		"authUrl":     authURL,
		"redirectUri": redirectURI,
		"state":       state,
		"message":     "Please open the authorization URL in your browser",
	})
}

// CancelAuth cancels an in-progress authentication flow
// POST /dashboard/api/cancel-auth
func (h *DashboardHandler) CancelAuth(c *gin.Context) {
	var req struct {
		State string `json:"state" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		JSONError(c, http.StatusBadRequest, "Invalid request: state is required")
		return
	}

	h.activeServersMux.Lock()
	server, ok := h.activeServers[req.State]
	if ok {
		// Remove it from the map immediately under lock
		delete(h.activeServers, req.State)
	}
	h.activeServersMux.Unlock()

	if !ok {
		logger.Warn("CancelAuth requested for an unknown or already completed state", logger.String("state", req.State))
		JSONError(c, http.StatusNotFound, "Authentication session not found or already completed.")
		return
	}

	// Stop the server outside the lock
	go server.Stop() // Use a goroutine to not block the response

	logger.Info("User cancelled authentication flow", logger.String("state", req.State))
	JSONSuccess(c, gin.H{"message": "Authentication process cancelled."})
}

// waitForCallback waits for OAuth callback and processes token exchange
func (h *DashboardHandler) waitForCallback(server *CallbackServer, state string) {
	defer func() {
		server.Stop()
		h.activeServersMux.Lock()
		delete(h.activeServers, state)
		h.activeServersMux.Unlock()
		logger.Info("Cleaned up callback server", logger.String("state", state))
	}()

	result, err := server.WaitForCallback()
	if err != nil {
		logger.Error("Callback failed", logger.String("state", state), logger.Err(err))
		return
	}

	// Process callback
	if err := h.processCallback(result.Code, result.State); err != nil {
		logger.Error("Failed to process callback", logger.Err(err))
	}
}

// Callback handles automatic OAuth callback
// GET /dashboard/callback?code=xxx&state=xxx
func (h *DashboardHandler) Callback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		logger.Error("Missing code or state in callback")
		RenderError(c, http.StatusBadRequest, "Missing code or state parameter")
		return
	}

	// Process callback
	if err := h.processCallback(code, state); err != nil {
		logger.Error("Failed to process callback", logger.Err(err))
		RenderError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to process callback: %v", err))
		return
	}

	// Render success page
	RenderSuccess(c, "Authentication successful! Token has been saved.")
}

// ManualCallback handles manual callback URL submission
// POST /dashboard/callback
// Body: {"callbackUrl": "http://127.0.0.1:12345/oauth/callback?code=xxx&state=xxx"}
func (h *DashboardHandler) ManualCallback(c *gin.Context) {
	var req struct {
		CallbackURL string `json:"callbackUrl" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error("Invalid request body", logger.Err(err))
		JSONError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Parse callback URL
	parsedURL, err := url.Parse(req.CallbackURL)
	if err != nil {
		logger.Error("Invalid callback URL", logger.Err(err))
		JSONError(c, http.StatusBadRequest, "Invalid callback URL format")
		return
	}

	// Extract code and state
	query := parsedURL.Query()
	code := query.Get("code")
	state := query.Get("state")

	if code == "" || state == "" {
		logger.Error("Missing code or state in callback URL")
		JSONError(c, http.StatusBadRequest, "Callback URL missing code or state parameter")
		return
	}

	// Process callback
	if err := h.processCallback(code, state); err != nil {
		logger.Error("Failed to process callback", logger.Err(err))
		JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to process callback: %v", err))
		return
	}

	JSONSuccess(c, gin.H{
		"message": "Authentication successful! Token has been saved.",
	})
}

// processCallback handles the common callback processing logic
func (h *DashboardHandler) processCallback(code, state string) error {
	// Validate state
	oauthState, err := h.stateStore.GetState(state)
	if err != nil {
		return fmt.Errorf("invalid state: %w", err)
	}

	// Delete state (one-time use)
	defer h.stateStore.DeleteState(state)

	// Get provider config
	providerConfig, err := GetProvider(oauthState.Provider)
	if err != nil {
		return fmt.Errorf("invalid provider: %w", err)
	}

	// Exchange code for tokens
	var accessToken, refreshToken, profileArn, clientIDHash string
	var expiresIn int
	var clientID, clientSecret, region string

	if providerConfig.AuthMethod == "Social" {
		// Use Kiro auth service
		tokenResp, err := h.kiroClient.CreateToken(CreateTokenParams{
			Code:         code,
			CodeVerifier: oauthState.CodeVerifier,
			RedirectURI:  oauthState.RedirectURI, // Use stored redirect URI for security
		})
		if err != nil {
			return fmt.Errorf("failed to exchange code for token: %w", err)
		}

		accessToken = tokenResp.AccessToken
		refreshToken = tokenResp.RefreshToken
		profileArn = tokenResp.ProfileArn
		expiresIn = tokenResp.ExpiresIn
	} else {
		// IdC: Use AWS SSO OIDC
		logger.Info("Exchanging authorization code for IdC tokens",
			logger.String("provider", oauthState.Provider))

		// Validate required fields
		if oauthState.ClientID == "" || oauthState.ClientSecret == "" {
			return fmt.Errorf("missing client credentials in OAuth state")
		}

		// Create AWS SSO client
		ssoClient := NewAWSSSOClient(oauthState.Region)

		// Exchange code for tokens
		tokenResp, err := ssoClient.CreateToken(TokenRequest{
			ClientID:     oauthState.ClientID,
			ClientSecret: oauthState.ClientSecret,
			GrantType:    "authorization_code",
			Code:         code,
			CodeVerifier: oauthState.CodeVerifier,
			RedirectURI:  oauthState.RedirectURI,
		})
		if err != nil {
			return fmt.Errorf("failed to exchange code for IdC token: %w", err)
		}

		accessToken = tokenResp.AccessToken
		refreshToken = tokenResp.RefreshToken
		expiresIn = tokenResp.ExpiresIn

		// Store client credentials for token refresh
		clientID = oauthState.ClientID
		clientSecret = oauthState.ClientSecret
		region = oauthState.Region

		// Generate clientIdHash from startUrl
		startURL := ssoClient.GetStartURL(oauthState.Provider, oauthState.StartURL)
		clientIDHash = GenerateClientIDHash(startURL)

		logger.Info("IdC token exchange successful",
			logger.String("provider", oauthState.Provider),
			logger.String("region", region))
	}

	// Create stored token
	tokenID := uuid.New().String()
	storedToken := &StoredToken{
		ID:           tokenID,
		AuthMethod:   providerConfig.AuthMethod,
		Provider:     oauthState.Provider,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ProfileArn:   profileArn,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
		CreatedAt:    time.Now(),
		Region:       region,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ClientIDHash: clientIDHash,
	}

	// Save token to file
	if err := SaveToken(storedToken, h.tokensDir); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	logger.Info("Token saved successfully",
		logger.String("token_id", tokenID),
		logger.String("provider", oauthState.Provider),
		logger.String("auth_method", providerConfig.AuthMethod))

	// 通知 AuthService 重新加载 tokens
	if h.authService != nil {
		if err := h.authService.ReloadTokensFromDirectory(h.tokensDir); err != nil {
			logger.Warn("Failed to reload tokens in AuthService",
				logger.Err(err))
			// 不返回错误，因为token已经保存成功
		} else {
			logger.Info("AuthService reloaded tokens successfully")
		}
	}

	return nil
}

// ListTokens returns list of all tokens (JSON API)
// GET /dashboard/tokens
func (h *DashboardHandler) ListTokens(c *gin.Context) {
	tokens, err := LoadTokens(h.tokensDir)
	if err != nil {
		logger.Error("Failed to load tokens", logger.Err(err))
		JSONError(c, http.StatusInternalServerError, "Failed to load tokens")
		return
	}

	// Mask sensitive fields
	type TokenResponse struct {
		ID         string            `json:"id"`
		AuthMethod string            `json:"authMethod"`
		Provider   string            `json:"provider"`
		ExpiresAt  time.Time         `json:"expiresAt"`
		CreatedAt  time.Time         `json:"createdAt"`
		Status     string            `json:"status"`
		Metadata   map[string]string `json:"metadata,omitempty"`
	}

	response := make([]TokenResponse, 0, len(tokens))
	for _, token := range tokens {
		status := "valid"
		if !token.ExpiresAt.IsZero() {
			timeUntilExpiry := time.Until(token.ExpiresAt)
			if timeUntilExpiry < 0 {
				status = "expired"
			} else if timeUntilExpiry < 24*time.Hour {
				status = "expiring"
			}
		}

		response = append(response, TokenResponse{
			ID:         token.ID,
			AuthMethod: token.AuthMethod,
			Provider:   token.Provider,
			ExpiresAt:  token.ExpiresAt,
			CreatedAt:  token.CreatedAt,
			Status:     status,
			Metadata:   token.Metadata,
		})
	}

	JSONSuccess(c, gin.H{
		"tokens": response,
		"count":  len(response),
	})
}

// RefreshToken refreshes a specific token
// POST /dashboard/tokens/refresh/:id
func (h *DashboardHandler) RefreshToken(c *gin.Context) {
	tokenID := c.Param("id")

	if tokenID == "" {
		JSONError(c, http.StatusBadRequest, "Token ID is required")
		return
	}

	// Load token
	token, err := GetTokenByID(tokenID, h.tokensDir)
	if err != nil {
		logger.Error("Token not found", logger.String("token_id", tokenID), logger.Err(err))
		JSONError(c, http.StatusNotFound, "Token not found")
		return
	}

	// Refresh token based on auth method
	var newAccessToken string
	var newRefreshToken string
	var expiresIn int

	if token.AuthMethod == "Social" {
		// Use Kiro auth service
		refreshResp, err := h.kiroClient.RefreshToken(RefreshTokenParams{
			RefreshToken: token.RefreshToken,
		})
		if err != nil {
			logger.Error("Failed to refresh token", logger.String("token_id", tokenID), logger.Err(err))
			JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to refresh token: %v", err))
			return
		}

		newAccessToken = refreshResp.AccessToken
		newRefreshToken = refreshResp.RefreshToken
		expiresIn = refreshResp.ExpiresIn
	} else if token.AuthMethod == "IdC" {
		// Use auth package's IdC refresh
		authConfig := auth.AuthConfig{
			AuthType:     auth.AuthMethodIdC,
			RefreshToken: token.RefreshToken,
			ClientID:     token.ClientID,
			ClientSecret: token.ClientSecret,
		}

		tokenInfo, err := auth.RefreshIdCToken(authConfig)
		if err != nil {
			logger.Error("Failed to refresh IdC token", logger.String("token_id", tokenID), logger.Err(err))
			JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to refresh token: %v", err))
			return
		}

		newAccessToken = tokenInfo.AccessToken
		newRefreshToken = token.RefreshToken // IdC refresh doesn't return new refresh token
		expiresIn = tokenInfo.ExpiresIn
	} else {
		JSONError(c, http.StatusBadRequest, "Unsupported auth method")
		return
	}

	// Update token
	token.AccessToken = newAccessToken
	if newRefreshToken != "" {
		token.RefreshToken = newRefreshToken
	}
	token.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Save updated token
	if err := SaveToken(token, h.tokensDir); err != nil {
		logger.Error("Failed to save refreshed token", logger.String("token_id", tokenID), logger.Err(err))
		JSONError(c, http.StatusInternalServerError, "Failed to save refreshed token")
		return
	}

	logger.Info("Token refreshed successfully", logger.String("token_id", tokenID))

	JSONSuccess(c, gin.H{
		"message":   "Token refreshed successfully",
		"expiresAt": token.ExpiresAt,
	})
}

// DeleteToken deletes a specific token
// DELETE /dashboard/tokens/:id
func (h *DashboardHandler) DeleteToken(c *gin.Context) {
	tokenID := c.Param("id")

	if tokenID == "" {
		JSONError(c, http.StatusBadRequest, "Token ID is required")
		return
	}

	// Delete token file
	if err := DeleteToken(tokenID, h.tokensDir); err != nil {
		logger.Error("Failed to delete token", logger.String("token_id", tokenID), logger.Err(err))
		JSONError(c, http.StatusNotFound, "Token not found or failed to delete")
		return
	}

	logger.Info("Token deleted successfully", logger.String("token_id", tokenID))

	JSONSuccess(c, gin.H{
		"message": "Token deleted successfully",
	})
}

// Stop stops the dashboard handler and cleans up resources
func (h *DashboardHandler) Stop() {
	if h.stateStore != nil {
		h.stateStore.Stop()
	}
	// Also stop any running callback servers
	h.activeServersMux.Lock()
	defer h.activeServersMux.Unlock()
	for state, server := range h.activeServers {
		logger.Info("Stopping lingering callback server on shutdown", logger.String("state", state))
		go server.Stop()
	}
	h.activeServers = make(map[string]*CallbackServer) // Clear the map
}

// GetStaticFS returns the embedded static filesystem
func GetStaticFS() fs.FS {
	staticFiles, err := fs.Sub(staticFS, "static")
	if err != nil {
		logger.Error("Failed to get static filesystem", logger.Err(err))
		return nil
	}
	return staticFiles
}

// SelectProvider renders the provider selection page
// GET /dashboard/select-provider
func (h *DashboardHandler) SelectProvider(c *gin.Context) {
	data := gin.H{
		"providers": ListProviders(),
	}

	// Try to render template, fallback to JSON
	if h.templates != nil {
		if err := h.templates.ExecuteTemplate(c.Writer, "select-provider.html", data); err != nil {
			logger.Error("Failed to render template", logger.Err(err))
			JSONSuccess(c, data)
		}
	} else {
		JSONSuccess(c, data)
	}
}

// ShowLogin renders the login page
// GET /dashboard/login (HTML version)
func (h *DashboardHandler) ShowLogin(c *gin.Context) {
	provider := c.Query("provider")
	startURL := c.Query("startUrl")

	// Validate provider
	_, err := GetProvider(provider)
	if err != nil {
		logger.Error("Invalid provider", logger.String("provider", provider), logger.Err(err))
		RenderError(c, http.StatusBadRequest, fmt.Sprintf("Invalid provider: %s", provider))
		return
	}

	data := gin.H{
		"provider": provider,
		"startUrl": startURL,
	}

	// Try to render template, fallback to JSON
	if h.templates != nil {
		if err := h.templates.ExecuteTemplate(c.Writer, "login.html", data); err != nil {
			logger.Error("Failed to render template", logger.Err(err))
JSONSuccess(c, data)
		}
	} else {
		JSONSuccess(c, data)
	}
}

// ShowManualCallback renders the manual callback submission page
// GET /dashboard/manual-callback
func (h *DashboardHandler) ShowManualCallback(c *gin.Context) {
	data := gin.H{}

	// Try to render template, fallback to JSON
	if h.templates != nil {
		if err := h.templates.ExecuteTemplate(c.Writer, "manual-callback.html", data); err != nil {
			logger.Error("Failed to render template", logger.Err(err))
			JSONSuccess(c, data)
		}
	} else {
		JSONSuccess(c, data)
	}
}
