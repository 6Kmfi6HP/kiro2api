package dashboard

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"kiro2api/logger"
)

// AWSSSOClient handles AWS SSO OIDC API calls
type AWSSSOClient struct {
	region     string
	baseURL    string
	httpClient *http.Client
}

// NewAWSSSOClient creates a new AWS SSO OIDC client
func NewAWSSSOClient(region string) *AWSSSOClient {
	if region == "" {
		region = "us-east-1"
	}

	return &AWSSSOClient{
		region:  region,
		baseURL: fmt.Sprintf("https://oidc.%s.amazonaws.com", region),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start URL constants
const (
	BuilderIDStartURL  = "https://view.awsapps.com/start"
	DefaultSSOStartURL = "https://amzn.awsapps.com/start"
)

// GetStartURL returns the correct start URL based on provider type
func (c *AWSSSOClient) GetStartURL(provider, startURL string) string {
	switch provider {
	case "BuilderId":
		return BuilderIDStartURL
	case "Enterprise":
		if startURL == "" {
			logger.Warn("Enterprise provider requires startUrl parameter")
			return DefaultSSOStartURL
		}
		return startURL
	case "Internal":
		if startURL != "" {
			return startURL
		}
		return DefaultSSOStartURL
	default:
		if startURL != "" {
			return startURL
		}
		return DefaultSSOStartURL
	}
}

// ClientRegistrationRequest represents OAuth client registration request
type ClientRegistrationRequest struct {
	ClientName   string   `json:"clientName"`
	ClientType   string   `json:"clientType"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grantTypes"`
	RedirectURIs []string `json:"redirectUris"`
	IssuerURL    string   `json:"issuerUrl"`
}

// ClientRegistrationResponse represents OAuth client registration response
type ClientRegistrationResponse struct {
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	ClientIDIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	TokenEndpoint         string `json:"tokenEndpoint"`
}

// RegisterClient registers a new OAuth client with AWS SSO OIDC
func (c *AWSSSOClient) RegisterClient(issuerURL string) (*ClientRegistrationResponse, error) {
	if issuerURL == "" {
		return nil, fmt.Errorf("issuerUrl is required for client registration")
	}

	// Default scopes for CodeWhisperer
	scopes := []string{
		"codewhisperer:completions",
		"codewhisperer:analysis",
		"codewhisperer:conversations",
		"codewhisperer:transformations",
		"codewhisperer:taskassist",
	}

	reqBody := ClientRegistrationRequest{
		ClientName:   "Kiro IDE",
		ClientType:   "public",
		Scopes:       scopes,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectURIs: []string{"http://127.0.0.1/oauth/callback"},
		IssuerURL:    issuerURL,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	registerURL := fmt.Sprintf("%s/client/register", c.baseURL)
	req, err := http.NewRequest(http.MethodPost, registerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aws-sdk-js/1.0.18 ua/2.1 os/darwin#25.0.0 lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E KiroIDE-0.2.13-66c23a8c5d15afabec89ef9954ef52a119f10d369df04d548fc6c1eac694b0d1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client registration failed: %d - %s", resp.StatusCode, string(body))
	}

	var clientResp ClientRegistrationResponse
	if err := json.Unmarshal(body, &clientResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	logger.Info("AWS SSO OIDC client registered",
		logger.String("client_id", clientResp.ClientID[:20]+"..."),
		logger.String("region", c.region))

	return &clientResp, nil
}

// TokenRequest represents token exchange request
type TokenRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	GrantType    string `json:"grantType"`
	Code         string `json:"code,omitempty"`
	CodeVerifier string `json:"codeVerifier,omitempty"`
	RedirectURI  string `json:"redirectUri,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

// AWSSSOTokenResponse represents token exchange response from AWS SSO OIDC
type AWSSSOTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	IDToken      string `json:"idToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
}

// CreateToken exchanges authorization code for access token
func (c *AWSSSOClient) CreateToken(params TokenRequest) (*AWSSSOTokenResponse, error) {
	jsonData, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	tokenURL := fmt.Sprintf("%s/token", c.baseURL)
	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aws-sdk-js/1.0.18 ua/2.1 os/darwin#25.0.0 lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E KiroIDE-0.2.13-66c23a8c5d15afabec89ef9954ef52a119f10d369df04d548fc6c1eac694b0d1")

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
		return nil, fmt.Errorf("token exchange failed: %d - %s", resp.StatusCode, string(body))
	}

	var tokenResp AWSSSOTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tokenResp, nil
}

// BuildAuthorizationURL constructs OAuth authorization URL
func (c *AWSSSOClient) BuildAuthorizationURL(params AuthorizationURLParams) (string, error) {
	if params.ClientID == "" {
		return "", fmt.Errorf("client ID is required")
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

	// Default scopes if not provided
	if len(params.Scopes) == 0 {
		params.Scopes = []string{
			"codewhisperer:completions",
			"codewhisperer:analysis",
			"codewhisperer:conversations",
			"codewhisperer:transformations",
			"codewhisperer:taskassist",
		}
	}

	// Build authorization URL
	authURL := fmt.Sprintf("%s/authorize", c.baseURL)
	u, err := url.Parse(authURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", params.ClientID)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("state", params.State)
	q.Set("code_challenge", params.CodeChallenge)
	q.Set("code_challenge_method", "S256")

	// Join scopes with comma (AWS SSO OIDC uses comma-separated scopes)
	scopeStr := ""
	for i, scope := range params.Scopes {
		if i > 0 {
			scopeStr += ","
		}
		scopeStr += scope
	}
	q.Set("scopes", scopeStr)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// GenerateClientIDHash generates SHA256 hash of start URL
func GenerateClientIDHash(startURL string) string {
	hash := sha256.Sum256([]byte(startURL))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
