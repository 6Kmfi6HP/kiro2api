package dashboard

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/google/uuid"
)

// GenerateCodeVerifier generates a cryptographically secure random string for PKCE
// Length: 43-128 characters (base64url encoded)
// Based on RFC 7636 Section 4.1
func GenerateCodeVerifier() (string, error) {
	// Generate 32 random bytes (will be 43 chars when base64url encoded)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Encode to base64url (RFC 4648 Section 5)
	verifier := base64.RawURLEncoding.EncodeToString(bytes)
	return verifier, nil
}

// GenerateCodeChallenge computes SHA256 hash of verifier and base64url encodes it
// Based on RFC 7636 Section 4.2
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return challenge
}

// GenerateState generates a random UUID v4 for CSRF protection
func GenerateState() string {
	return uuid.New().String()
}

// PKCEParams holds PKCE parameters for OAuth flow
type PKCEParams struct {
	CodeVerifier  string
	CodeChallenge string
	Method        string // Always "S256" for SHA256
}

// GeneratePKCE generates complete PKCE parameters
func GeneratePKCE() (*PKCEParams, error) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}

	challenge := GenerateCodeChallenge(verifier)

	return &PKCEParams{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Method:        "S256",
	}, nil
}

// AuthorizationURLParams holds parameters for building authorization URL
type AuthorizationURLParams struct {
	BaseURL       string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	State         string
	Scopes        []string
}

// BuildAuthorizationURL constructs OAuth authorization URL
// Different URLs for Social vs IdC providers
func BuildAuthorizationURL(params AuthorizationURLParams) (string, error) {
	if params.BaseURL == "" {
		return "", fmt.Errorf("base URL is required")
	}
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

	// Parse base URL
	u, err := url.Parse(params.BaseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	// Build query parameters
	q := u.Query()
	q.Set("client_id", params.ClientID)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("code_challenge", params.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", params.State)
	q.Set("response_type", "code")

	// Add scopes if provided
	if len(params.Scopes) > 0 {
		scope := ""
		for i, s := range params.Scopes {
			if i > 0 {
				scope += " "
			}
			scope += s
		}
		q.Set("scope", scope)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TokenExchangeParams holds parameters for token exchange
type TokenExchangeParams struct {
	Code         string
	CodeVerifier string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	GrantType    string // "authorization_code" or "refresh_token"
	RefreshToken string // Only for refresh_token grant
}

// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}
