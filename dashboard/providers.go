package dashboard

import (
	"fmt"
)

// OAuthProvider defines OAuth provider configuration
type OAuthProvider struct {
	ID               string   // Provider ID (e.g., "BuilderId", "Google")
	Name             string   // Display name
	AuthMethod       string   // "Social" or "IdC"
	AuthorizationURL string   // Authorization endpoint
	TokenURL         string   // Token endpoint
	Scopes           []string // OAuth scopes
	RedirectPorts    []int    // For Social providers (predefined ports)
}

// Predefined ports for Social authentication
// Based on Kiro's implementation (line 107891)
var SocialAuthPorts = []int{49153, 50153, 51153, 52153, 53153, 4649, 6588, 9091, 8008, 3128}

// Provider configurations
var providers = map[string]*OAuthProvider{
	// IdC Providers (AWS SSO OIDC)
	// IMPORTANT: Must use CodeWhisperer scopes, not OpenID scopes
	"BuilderId": {
		ID:         "BuilderId",
		Name:       "AWS Builder ID",
		AuthMethod: "IdC",
		Scopes: []string{
			"codewhisperer:completions",
			"codewhisperer:analysis",
			"codewhisperer:conversations",
			"codewhisperer:transformations",
			"codewhisperer:taskassist",
		},
	},
	"Enterprise": {
		ID:         "Enterprise",
		Name:       "AWS Enterprise SSO",
		AuthMethod: "IdC",
		Scopes: []string{
			"codewhisperer:completions",
			"codewhisperer:analysis",
			"codewhisperer:conversations",
			"codewhisperer:transformations",
			"codewhisperer:taskassist",
		},
	},
	"Internal": {
		ID:         "Internal",
		Name:       "AWS Internal SSO",
		AuthMethod: "IdC",
		Scopes: []string{
			"codewhisperer:completions",
			"codewhisperer:analysis",
			"codewhisperer:conversations",
			"codewhisperer:transformations",
			"codewhisperer:taskassist",
		},
	},

	// Social Providers (Kiro Auth Service)
	"Google": {
		ID:               "Google",
		Name:             "Google",
		AuthMethod:       "Social",
		AuthorizationURL: "https://prod.us-east-1.auth.desktop.kiro.dev/login",
		TokenURL:         "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token",
		Scopes:           []string{},
		RedirectPorts:    SocialAuthPorts,
	},
	"Github": {
		ID:               "Github",
		Name:             "GitHub",
		AuthMethod:       "Social",
		AuthorizationURL: "https://prod.us-east-1.auth.desktop.kiro.dev/login",
		TokenURL:         "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token",
		Scopes:           []string{},
		RedirectPorts:    SocialAuthPorts,
	},
}

// GetProvider returns provider configuration by ID
func GetProvider(providerID string) (*OAuthProvider, error) {
	provider, ok := providers[providerID]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s. Supported providers: %v", providerID, ListProviders())
	}

	// Return a copy to prevent modification
	providerCopy := *provider
	return &providerCopy, nil
}

// ListProviders returns all available provider IDs
func ListProviders() []string {
	ids := make([]string, 0, len(providers))
	for id := range providers {
		ids = append(ids, id)
	}
	return ids
}

// IsIdCProvider checks if provider uses IdC authentication
func IsIdCProvider(providerID string) bool {
	provider, err := GetProvider(providerID)
	if err != nil {
		return false
	}
	return provider.AuthMethod == "IdC"
}

// IsSocialProvider checks if provider uses Social authentication
func IsSocialProvider(providerID string) bool {
	provider, err := GetProvider(providerID)
	if err != nil {
		return false
	}
	return provider.AuthMethod == "Social"
}
