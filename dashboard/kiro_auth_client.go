package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// KiroAuthClient is a client for Kiro's authentication service
// Used for social authentication (Google, GitHub)
type KiroAuthClient struct {
	endpoint   string
	httpClient *http.Client
}

// NewKiroAuthClient creates a new Kiro auth service client
func NewKiroAuthClient() *KiroAuthClient {
	return &KiroAuthClient{
		endpoint: "https://prod.us-east-1.auth.desktop.kiro.dev",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// LoginParams holds parameters for login
type LoginParams struct {
	Provider      string // "Google" or "Github"
	RedirectURI   string
	CodeChallenge string
	State         string
}

// GetLoginURL builds the login URL for browser
func (c *KiroAuthClient) GetLoginURL(params LoginParams) (string, error) {
	if params.Provider == "" {
		return "", fmt.Errorf("provider is required")
	}
	if params.RedirectURI == "" {
		return "", fmt.Errorf("redirect URI is required")
	}
	if params.CodeChallenge == "" {
		return "", fmt.Errorf("code challenge is required")
	}
	if params.State == "" {
		return "", fmt.Errorf("state is required")
	}

	// Build login URL with query parameters
	loginURL := fmt.Sprintf("%s/login", c.endpoint)
	u, err := url.Parse(loginURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse login URL: %w", err)
	}

	q := u.Query()
	q.Set("idp", params.Provider)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("code_challenge", params.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", params.State)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// CreateTokenParams holds parameters for token creation
type CreateTokenParams struct {
	Code           string
	CodeVerifier   string
	RedirectURI    string
	InvitationCode string // Optional
}

// CreateTokenResponse represents token creation response
type CreateTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ProfileArn   string `json:"profileArn"`
	IDToken      string `json:"idToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
}

// CreateToken exchanges authorization code for access token
func (c *KiroAuthClient) CreateToken(params CreateTokenParams) (*CreateTokenResponse, error) {
	if params.Code == "" {
		return nil, fmt.Errorf("code is required")
	}
	if params.CodeVerifier == "" {
		return nil, fmt.Errorf("code verifier is required")
	}
	if params.RedirectURI == "" {
		return nil, fmt.Errorf("redirect URI is required")
	}

	// Build request body
	reqBody := map[string]string{
		"code":          params.Code,
		"code_verifier": params.CodeVerifier,
		"redirect_uri":  params.RedirectURI,
	}
	if params.InvitationCode != "" {
		reqBody["invitation_code"] = params.InvitationCode
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make POST request
	tokenURL := fmt.Sprintf("%s/oauth/token", c.endpoint)
	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Kiro2API/1.0.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tokenResp, nil
}

// RefreshTokenParams holds parameters for token refresh
type RefreshTokenParams struct {
	RefreshToken string
}

// RefreshTokenResponse represents token refresh response
type RefreshTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ProfileArn   string `json:"profileArn"`
	IDToken      string `json:"idToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
}

// RefreshToken refreshes an existing access token
func (c *KiroAuthClient) RefreshToken(params RefreshTokenParams) (*RefreshTokenResponse, error) {
	if params.RefreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	// Build request body
	reqBody := map[string]string{
		"refreshToken": params.RefreshToken,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make POST request
	refreshURL := fmt.Sprintf("%s/refreshToken", c.endpoint)
	req, err := http.NewRequest(http.MethodPost, refreshURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Kiro2API/1.0.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: %d - %s", resp.StatusCode, string(body))
	}

	var tokenResp RefreshTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tokenResp, nil
}

// LogoutParams holds parameters for logout
type LogoutParams struct {
	RefreshToken string
}

// Logout invalidates a refresh token
func (c *KiroAuthClient) Logout(params LogoutParams) error {
	if params.RefreshToken == "" {
		return fmt.Errorf("refresh token is required")
	}

	// Build request body
	reqBody := map[string]string{
		"refreshToken": params.RefreshToken,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make POST request
	logoutURL := fmt.Sprintf("%s/logout", c.endpoint)
	req, err := http.NewRequest(http.MethodPost, logoutURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Kiro2API/1.0.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logout failed: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}
