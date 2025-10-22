package dashboard

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestGenerateCodeVerifier tests PKCE code verifier generation
func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier failed: %v", err)
	}

	// Check length (should be 43 chars for 32 bytes base64url encoded)
	if len(verifier) != 43 {
		t.Errorf("Expected verifier length 43, got %d", len(verifier))
	}

	// Check that it's valid base64url
	_, err = base64.RawURLEncoding.DecodeString(verifier)
	if err != nil {
		t.Errorf("Verifier is not valid base64url: %v", err)
	}

	// Generate multiple verifiers and ensure they're different (randomness check)
	verifiers := make(map[string]bool)
	for i := 0; i < 10; i++ {
		v, err := GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("GenerateCodeVerifier failed on iteration %d: %v", i, err)
		}
		if verifiers[v] {
			t.Errorf("Duplicate verifier generated: %s", v)
		}
		verifiers[v] = true
	}
}

// TestGenerateCodeChallenge tests PKCE code challenge generation
func TestGenerateCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := GenerateCodeChallenge(verifier)

	// Manually compute expected challenge
	hash := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	if challenge != expected {
		t.Errorf("Challenge mismatch.\nExpected: %s\nGot: %s", expected, challenge)
	}

	// Check that it's valid base64url
	_, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		t.Errorf("Challenge is not valid base64url: %v", err)
	}

	// Check length (SHA256 hash is 32 bytes, base64url encoded is 43 chars)
	if len(challenge) != 43 {
		t.Errorf("Expected challenge length 43, got %d", len(challenge))
	}
}

// TestGenerateState tests state generation
func TestGenerateState(t *testing.T) {
	state := GenerateState()

	// Check that it's a valid UUID v4
	_, err := uuid.Parse(state)
	if err != nil {
		t.Errorf("State is not a valid UUID: %v", err)
	}

	// Generate multiple states and ensure they're different
	states := make(map[string]bool)
	for i := 0; i < 10; i++ {
		s := GenerateState()
		if states[s] {
			t.Errorf("Duplicate state generated: %s", s)
		}
		states[s] = true
	}
}

// TestGeneratePKCE tests complete PKCE generation
func TestGeneratePKCE(t *testing.T) {
	pkce, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE failed: %v", err)
	}

	if pkce.CodeVerifier == "" {
		t.Error("CodeVerifier is empty")
	}
	if pkce.CodeChallenge == "" {
		t.Error("CodeChallenge is empty")
	}
	if pkce.Method != "S256" {
		t.Errorf("Expected method S256, got %s", pkce.Method)
	}

	// Verify challenge matches verifier
	expectedChallenge := GenerateCodeChallenge(pkce.CodeVerifier)
	if pkce.CodeChallenge != expectedChallenge {
		t.Error("Challenge does not match verifier")
	}
}

// TestBuildAuthorizationURL tests authorization URL construction
func TestBuildAuthorizationURL(t *testing.T) {
	params := AuthorizationURLParams{
		BaseURL:       "https://example.com/authorize",
		ClientID:      "test-client-id",
		RedirectURI:   "http://localhost:8080/callback",
		CodeChallenge: "test-challenge",
		State:         "test-state",
		Scopes:        []string{"openid", "profile"},
	}

	url, err := BuildAuthorizationURL(params)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	// Check that URL contains required parameters
	if !strings.Contains(url, "client_id=test-client-id") {
		t.Error("URL missing client_id")
	}
	if !strings.Contains(url, "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback") {
		t.Error("URL missing or incorrectly encoded redirect_uri")
	}
	if !strings.Contains(url, "code_challenge=test-challenge") {
		t.Error("URL missing code_challenge")
	}
	if !strings.Contains(url, "code_challenge_method=S256") {
		t.Error("URL missing code_challenge_method")
	}
	if !strings.Contains(url, "state=test-state") {
		t.Error("URL missing state")
	}
	if !strings.Contains(url, "response_type=code") {
		t.Error("URL missing response_type")
	}
	if !strings.Contains(url, "scope=openid+profile") {
		t.Error("URL missing or incorrectly encoded scope")
	}
}

// TestBuildAuthorizationURL_Validation tests parameter validation
func TestBuildAuthorizationURL_Validation(t *testing.T) {
	tests := []struct {
		name    string
		params  AuthorizationURLParams
		wantErr string
	}{
		{
			name: "missing base URL",
			params: AuthorizationURLParams{
				ClientID:      "test",
				RedirectURI:   "http://localhost",
				CodeChallenge: "test",
				State:         "test",
			},
			wantErr: "base URL is required",
		},
		{
			name: "missing client ID",
			params: AuthorizationURLParams{
				BaseURL:       "https://example.com",
				RedirectURI:   "http://localhost",
				CodeChallenge: "test",
				State:         "test",
			},
			wantErr: "client ID is required",
		},
		{
			name: "missing redirect URI",
			params: AuthorizationURLParams{
				BaseURL:       "https://example.com",
				ClientID:      "test",
				CodeChallenge: "test",
				State:         "test",
			},
			wantErr: "redirect URI is required",
		},
		{
			name: "missing code challenge",
			params: AuthorizationURLParams{
				BaseURL:     "https://example.com",
				ClientID:    "test",
				RedirectURI: "http://localhost",
				State:       "test",
			},
			wantErr: "code challenge is required",
		},
		{
			name: "missing state",
			params: AuthorizationURLParams{
				BaseURL:       "https://example.com",
				ClientID:      "test",
				RedirectURI:   "http://localhost",
				CodeChallenge: "test",
			},
			wantErr: "state is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildAuthorizationURL(tt.params)
			if err == nil {
				t.Error("Expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// TestStateStore tests state storage and retrieval
func TestStateStore(t *testing.T) {
	store := NewStateStore()
	defer store.Stop()

	state := "test-state-123"
	data := &OAuthState{
		State:         state,
		CodeVerifier:  "test-verifier",
		CodeChallenge: "test-challenge",
		Provider:      "Google",
		Region:        "us-east-1",
	}

	// Save state
	err := store.SaveState(state, data)
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Retrieve state
	retrieved, err := store.GetState(state)
	if err != nil {
		t.Fatalf("GetState failed: %v", err)
	}

	if retrieved.State != data.State {
		t.Errorf("State mismatch: expected %s, got %s", data.State, retrieved.State)
	}
	if retrieved.CodeVerifier != data.CodeVerifier {
		t.Errorf("CodeVerifier mismatch: expected %s, got %s", data.CodeVerifier, retrieved.CodeVerifier)
	}
	if retrieved.Provider != data.Provider {
		t.Errorf("Provider mismatch: expected %s, got %s", data.Provider, retrieved.Provider)
	}

	// Delete state
	store.DeleteState(state)

	// Verify deletion
	_, err = store.GetState(state)
	if err == nil {
		t.Error("Expected error after deletion, got nil")
	}
}

// TestStateStore_Expiration tests state TTL and cleanup
func TestStateStore_Expiration(t *testing.T) {
	store := NewStateStore()
	defer store.Stop()

	state := "test-state-expire"
	data := &OAuthState{
		State:        state,
		CodeVerifier: "test-verifier",
		Provider:     "Google",
	}

	// Save state
	err := store.SaveState(state, data)
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Manually set expiration to past
	retrieved, _ := store.GetState(state)
	retrieved.ExpiresAt = time.Now().Add(-1 * time.Minute)
	store.states.Store(state, retrieved)

	// Try to retrieve expired state
	_, err = store.GetState(state)
	if err == nil {
		t.Error("Expected error for expired state, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Expected 'expired' error, got: %v", err)
	}
}

// TestStateStore_CleanupExpired tests cleanup of expired states
func TestStateStore_CleanupExpired(t *testing.T) {
	store := NewStateStore()
	defer store.Stop()

	// Add multiple states
	for i := 0; i < 5; i++ {
		state := GenerateState()
		data := &OAuthState{
			State:        state,
			CodeVerifier: "test-verifier",
			Provider:     "Google",
		}
		store.SaveState(state, data)
	}

	// Verify count
	if store.Count() != 5 {
		t.Errorf("Expected 5 states, got %d", store.Count())
	}

	// Expire 3 states
	count := 0
	store.states.Range(func(key, value interface{}) bool {
		if count < 3 {
			data := value.(*OAuthState)
			data.ExpiresAt = time.Now().Add(-1 * time.Minute)
			store.states.Store(key, data)
			count++
		}
		return true
	})

	// Run cleanup
	cleaned := store.CleanupExpired()
	if cleaned != 3 {
		t.Errorf("Expected 3 states cleaned, got %d", cleaned)
	}

	// Verify remaining count
	if store.Count() != 2 {
		t.Errorf("Expected 2 states remaining, got %d", store.Count())
	}
}

// TestCallbackServer tests callback server start/stop
func TestCallbackServer(t *testing.T) {
	server := NewCallbackServer(CallbackServerOptions{
		Strategy: "random",
		Hostname: "127.0.0.1",
		Timeout:  5 * time.Second,
	})

	// Start server
	redirectURI, err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	if !strings.HasPrefix(redirectURI, "http://127.0.0.1:") {
		t.Errorf("Invalid redirect URI: %s", redirectURI)
	}
	if !strings.HasSuffix(redirectURI, "/oauth/callback") {
		t.Errorf("Redirect URI missing /oauth/callback path: %s", redirectURI)
	}

	// Stop server
	err = server.Stop()
	if err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}
}

// TestCallbackServer_SuccessCallback tests successful OAuth callback
func TestCallbackServer_SuccessCallback(t *testing.T) {
	server := NewCallbackServer(CallbackServerOptions{
		Strategy: "random",
		Hostname: "127.0.0.1",
		Timeout:  5 * time.Second,
	})

	redirectURI, err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Simulate OAuth callback
	go func() {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get(redirectURI + "?code=test-code&state=test-state")
		if err != nil {
			t.Errorf("Failed to make callback request: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	}()

	// Wait for callback
	result, err := server.WaitForCallback()
	if err != nil {
		t.Fatalf("WaitForCallback failed: %v", err)
	}

	if result.Code != "test-code" {
		t.Errorf("Expected code 'test-code', got '%s'", result.Code)
	}
	if result.State != "test-state" {
		t.Errorf("Expected state 'test-state', got '%s'", result.State)
	}
}

// TestCallbackServer_ErrorCallback tests OAuth error callback
func TestCallbackServer_ErrorCallback(t *testing.T) {
	server := NewCallbackServer(CallbackServerOptions{
		Strategy: "random",
		Hostname: "127.0.0.1",
		Timeout:  5 * time.Second,
	})

	redirectURI, err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Simulate OAuth error callback
	go func() {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get(redirectURI + "?error=access_denied&error_description=User+denied+access")
		if err != nil {
			t.Errorf("Failed to make callback request: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", resp.StatusCode)
		}
	}()

	// Wait for callback
	_, err = server.WaitForCallback()
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("Expected 'access_denied' error, got: %v", err)
	}
}

// TestProviderConfiguration tests provider factory
func TestProviderConfiguration(t *testing.T) {
	// Test valid providers
	validProviders := []string{"BuilderId", "Enterprise", "Google", "Github"}
	for _, id := range validProviders {
		provider, err := GetProvider(id)
		if err != nil {
			t.Errorf("GetProvider(%s) failed: %v", id, err)
		}
		if provider.ID != id {
			t.Errorf("Provider ID mismatch: expected %s, got %s", id, provider.ID)
		}
	}

	// Test invalid provider
	_, err := GetProvider("InvalidProvider")
	if err == nil {
		t.Error("Expected error for invalid provider, got nil")
	}

	// Test ListProviders
	providers := ListProviders()
	if len(providers) < 4 {
		t.Errorf("Expected at least 4 providers, got %d", len(providers))
	}

	// Test IsIdCProvider
	if !IsIdCProvider("BuilderId") {
		t.Error("BuilderId should be IdC provider")
	}
	if IsIdCProvider("Google") {
		t.Error("Google should not be IdC provider")
	}

	// Test IsSocialProvider
	if !IsSocialProvider("Google") {
		t.Error("Google should be Social provider")
	}
	if IsSocialProvider("BuilderId") {
		t.Error("BuilderId should not be Social provider")
	}
}

// TestKiroAuthClient_GetLoginURL tests login URL generation
func TestKiroAuthClient_GetLoginURL(t *testing.T) {
	client := NewKiroAuthClient()

	params := LoginParams{
		Provider:      "Google",
		RedirectURI:   "http://localhost:49153/oauth/callback",
		CodeChallenge: "test-challenge",
		State:         "test-state",
	}

	url, err := client.GetLoginURL(params)
	if err != nil {
		t.Fatalf("GetLoginURL failed: %v", err)
	}

	if !strings.Contains(url, "idp=Google") {
		t.Error("URL missing idp parameter")
	}
	if !strings.Contains(url, "code_challenge=test-challenge") {
		t.Error("URL missing code_challenge")
	}
	if !strings.Contains(url, "code_challenge_method=S256") {
		t.Error("URL missing code_challenge_method")
	}
	if !strings.Contains(url, "state=test-state") {
		t.Error("URL missing state")
	}
}

// TestKiroAuthClient_CreateToken tests token creation with mock server
func TestKiroAuthClient_CreateToken(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Return mock token response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"accessToken": "test-access-token",
			"refreshToken": "test-refresh-token",
			"profileArn": "arn:aws:profile/test",
			"idToken": "test-id-token",
			"tokenType": "Bearer",
			"expiresIn": 3600
		}`))
	}))
	defer server.Close()

	// Create client with mock endpoint
	client := &KiroAuthClient{
		endpoint:   server.URL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	params := CreateTokenParams{
		Code:         "test-code",
		CodeVerifier: "test-verifier",
		RedirectURI:  "http://localhost:49153/oauth/callback",
	}

	resp, err := client.CreateToken(params)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	if resp.AccessToken != "test-access-token" {
		t.Errorf("Expected access token 'test-access-token', got '%s'", resp.AccessToken)
	}
	if resp.RefreshToken != "test-refresh-token" {
		t.Errorf("Expected refresh token 'test-refresh-token', got '%s'", resp.RefreshToken)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("Expected expiresIn 3600, got %d", resp.ExpiresIn)
	}
}
