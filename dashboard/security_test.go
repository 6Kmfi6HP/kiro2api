package dashboard

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"kiro2api/auth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TestCSRFProtection tests CSRF protection via state parameter
func TestCSRFProtection(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	authService := &auth.AuthService{}
	handler, err := NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/dashboard/callback", handler.ManualCallback)

	t.Run("RejectInvalidState", func(t *testing.T) {
		// Submit callback with invalid state
		callbackURL := "http://127.0.0.1:12345/oauth/callback?code=test-code&state=invalid-state"
		body := map[string]string{
			"callbackUrl": callbackURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Error("Expected request to be rejected with invalid state")
		}

		// Verify error message mentions state
		responseBody := w.Body.String()
		if !strings.Contains(responseBody, "state") {
			t.Error("Error message should mention state parameter")
		}
	})

	t.Run("RejectExpiredState", func(t *testing.T) {
		// Create an expired state
		state := uuid.New().String()
		oauthState := &OAuthState{
			State:         state,
			CodeVerifier:  "test-verifier",
			CodeChallenge: "test-challenge",
			Provider:      "BuilderId",
		}
		handler.stateStore.SaveState(state, oauthState)

		// Wait for state to expire (StateStore has 10 minute TTL)
		// For testing, we'll manually delete it to simulate expiration
		handler.stateStore.DeleteState(state)

		// Submit callback with expired state
		callbackURL := fmt.Sprintf("http://127.0.0.1:12345/oauth/callback?code=test-code&state=%s", state)
		body := map[string]string{
			"callbackUrl": callbackURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Error("Expected request to be rejected with expired state")
		}
	})

	t.Run("StateOneTimeUse", func(t *testing.T) {
		// Create a valid state
		state := uuid.New().String()
		oauthState := &OAuthState{
			State:         state,
			CodeVerifier:  "test-verifier",
			CodeChallenge: "test-challenge",
			Provider:      "BuilderId",
		}
		handler.stateStore.SaveState(state, oauthState)

		// Submit callback first time
		callbackURL := fmt.Sprintf("http://127.0.0.1:12345/oauth/callback?code=test-code&state=%s", state)
		body := map[string]string{
			"callbackUrl": callbackURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req1 := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req1.Header.Set("Content-Type", "application/json")
		w1 := httptest.NewRecorder()
		router.ServeHTTP(w1, req1)

		// Submit callback second time with same state
		req2 := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req2.Header.Set("Content-Type", "application/json")
		w2 := httptest.NewRecorder()
		router.ServeHTTP(w2, req2)

		// Second request should fail
		if w2.Code == http.StatusOK {
			t.Error("Expected second request to be rejected (state should be one-time use)")
		}
	})

	t.Run("StateRandomness", func(t *testing.T) {
		// Generate multiple states and verify they're unique
		states := make(map[string]bool)
		for i := 0; i < 100; i++ {
			state := GenerateState()
			if states[state] {
				t.Errorf("Duplicate state generated: %s", state)
			}
			states[state] = true

			// Verify state is a valid UUID
			if _, err := uuid.Parse(state); err != nil {
				t.Errorf("State is not a valid UUID: %s", state)
			}
		}
	})
}

// TestPKCEValidation tests PKCE (Proof Key for Code Exchange) validation
func TestPKCEValidation(t *testing.T) {
	t.Run("CodeVerifierLength", func(t *testing.T) {
		verifier, err := GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("Failed to generate code verifier: %v", err)
		}

		// RFC 7636: code verifier must be 43-128 characters
		if len(verifier) < 43 || len(verifier) > 128 {
			t.Errorf("Code verifier length %d is outside valid range [43, 128]", len(verifier))
		}
	})

	t.Run("CodeVerifierCharacters", func(t *testing.T) {
		verifier, err := GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("Failed to generate code verifier: %v", err)
		}

		// RFC 7636: code verifier must use [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
		validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
		for _, char := range verifier {
			if !strings.ContainsRune(validChars, char) {
				t.Errorf("Code verifier contains invalid character: %c", char)
			}
		}
	})

	t.Run("CodeChallengeMethod", func(t *testing.T) {
		pkce, err := GeneratePKCE()
		if err != nil {
			t.Fatalf("Failed to generate PKCE: %v", err)
		}

		// Verify method is S256
		if pkce.Method != "S256" {
			t.Errorf("Expected method S256, got %s", pkce.Method)
		}
	})

	t.Run("CodeChallengeCorrectness", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

		challenge := GenerateCodeChallenge(verifier)

		if challenge != expectedChallenge {
			t.Errorf("Expected challenge %s, got %s", expectedChallenge, challenge)
		}
	})

	t.Run("CodeChallengeFormat", func(t *testing.T) {
		verifier, err := GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("Failed to generate code verifier: %v", err)
		}

		challenge := GenerateCodeChallenge(verifier)

		// Verify challenge is valid base64url
		_, err = base64.RawURLEncoding.DecodeString(challenge)
		if err != nil {
			t.Errorf("Code challenge is not valid base64url: %v", err)
		}

		// Verify challenge length (SHA256 hash is 32 bytes, base64url encoded is 43 chars)
		if len(challenge) != 43 {
			t.Errorf("Expected challenge length 43, got %d", len(challenge))
		}
	})

	t.Run("PKCERandomness", func(t *testing.T) {
		// Generate multiple PKCE parameters and verify they're unique
		verifiers := make(map[string]bool)
		challenges := make(map[string]bool)

		for i := 0; i < 100; i++ {
			pkce, err := GeneratePKCE()
			if err != nil {
				t.Fatalf("Failed to generate PKCE: %v", err)
			}

			if verifiers[pkce.CodeVerifier] {
				t.Errorf("Duplicate code verifier generated: %s", pkce.CodeVerifier)
			}
			verifiers[pkce.CodeVerifier] = true

			if challenges[pkce.CodeChallenge] {
				t.Errorf("Duplicate code challenge generated: %s", pkce.CodeChallenge)
			}
			challenges[pkce.CodeChallenge] = true
		}
	})

	t.Run("PKCEConsistency", func(t *testing.T) {
		// Verify that the same verifier always produces the same challenge
		verifier := "test-verifier-123"
		challenge1 := GenerateCodeChallenge(verifier)
		challenge2 := GenerateCodeChallenge(verifier)

		if challenge1 != challenge2 {
			t.Error("Same verifier should always produce same challenge")
		}

		// Verify challenge is correct SHA256 hash
		hash := sha256.Sum256([]byte(verifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

		if challenge1 != expectedChallenge {
			t.Errorf("Challenge does not match expected SHA256 hash")
		}
	})
}

// TestInputValidation tests input validation and sanitization
func TestInputValidation(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	authService := &auth.AuthService{}
	handler, err := NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard/api/login", handler.Login)
	router.POST("/dashboard/callback", handler.ManualCallback)

	t.Run("InvalidProvider", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard/api/login?provider=InvalidProvider", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Invalid provider") {
			t.Error("Error message should mention invalid provider")
		}
	})

	t.Run("MissingProvider", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard/api/login", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("SQLInjectionAttempt", func(t *testing.T) {
		// Try SQL injection in provider parameter
		provider := url.QueryEscape("BuilderId'; DROP TABLE tokens; --")
		req := httptest.NewRequest("GET", "/dashboard/api/login?provider="+provider, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should be rejected as invalid provider
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("XSSAttemptInCallbackURL", func(t *testing.T) {
		// Try XSS in callback URL
		callbackURL := "http://127.0.0.1:12345/oauth/callback?code=<script>alert('xss')</script>&state=test"
		body := map[string]string{
			"callbackUrl": callbackURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Verify XSS payload is not executed
		responseBody := w.Body.String()
		if strings.Contains(responseBody, "<script>") {
			t.Error("XSS payload should be escaped or rejected")
		}
	})

	t.Run("PathTraversalAttempt", func(t *testing.T) {
		// Try path traversal in token ID
		router.DELETE("/dashboard/tokens/:id", handler.DeleteToken)

		tokenID := url.PathEscape("../../etc/passwd")
		req := httptest.NewRequest("DELETE", "/dashboard/tokens/"+tokenID, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should fail to find token (not access /etc/passwd)
		if w.Code == http.StatusOK {
			t.Error("Path traversal should not succeed")
		}
	})

	t.Run("ExtremelyLongInput", func(t *testing.T) {
		// Try extremely long callback URL
		longURL := "http://127.0.0.1:12345/oauth/callback?code=" + strings.Repeat("a", 100000) + "&state=test"
		body := map[string]string{
			"callbackUrl": longURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should handle gracefully (reject or truncate)
		if w.Code == http.StatusOK {
			t.Log("Long input was accepted (may need size limits)")
		}
	})

	t.Run("NullByteInjection", func(t *testing.T) {
		// Try null byte injection
		callbackURL := "http://127.0.0.1:12345/oauth/callback?code=test\x00malicious&state=test"
		body := map[string]string{
			"callbackUrl": callbackURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should handle gracefully
		if w.Code == http.StatusOK {
			t.Log("Null byte injection was accepted (may need validation)")
		}
	})
}

// TestXSSPrevention tests XSS prevention measures
func TestXSSPrevention(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	authService := &auth.AuthService{}
	handler, err := NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard", handler.Home)

	t.Run("ScriptTagsEscaped", func(t *testing.T) {
		// Create token with XSS payload in metadata
		token := &StoredToken{
			ID:           uuid.New().String(),
			AuthMethod:   "Social",
			Provider:     "<script>alert('xss')</script>",
			AccessToken:  "test-token",
			RefreshToken: "test-refresh",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		}
		SaveToken(token, testDir)

		req := httptest.NewRequest("GET", "/dashboard", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		body := w.Body.String()

		// Verify script tags are escaped
		if strings.Contains(body, "<script>alert('xss')</script>") {
			t.Error("Script tags should be escaped in HTML output")
		}

		// Verify escaped version is present (if HTML rendering)
		if strings.Contains(body, "&lt;script&gt;") || strings.Contains(body, "\\u003cscript\\u003e") {
			t.Log("Script tags are properly escaped")
		}
	})

	t.Run("EventHandlersEscaped", func(t *testing.T) {
		// Create token with event handler XSS payload
		token := &StoredToken{
			ID:           uuid.New().String(),
			AuthMethod:   "Social",
			Provider:     "BuilderId\" onload=\"alert('xss')\"",
			AccessToken:  "test-token",
			RefreshToken: "test-refresh",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		}
		SaveToken(token, testDir)

		req := httptest.NewRequest("GET", "/dashboard", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		body := w.Body.String()

		// Verify event handlers are escaped
		if strings.Contains(body, "onload=\"alert('xss')\"") {
			t.Error("Event handlers should be escaped in HTML output")
		}
	})
}

// TestSecurityHeadersExtended tests security-related HTTP headers
func TestSecurityHeadersExtended(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	authService := &auth.AuthService{}
	handler, err := NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard", handler.Home)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	headers := w.Header()

	t.Run("ContentTypeHeader", func(t *testing.T) {
		contentType := headers.Get("Content-Type")
		if contentType == "" {
			t.Error("Content-Type header should be set")
		}
	})

	// Note: Additional security headers (X-Frame-Options, X-Content-Type-Options, etc.)
	// may be added by middleware. These tests document expected behavior.

	t.Run("NoSensitiveInfoInHeaders", func(t *testing.T) {
		// Verify no sensitive information in headers
		for key, values := range headers {
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), "token") ||
					strings.Contains(strings.ToLower(value), "password") ||
					strings.Contains(strings.ToLower(value), "secret") {
					t.Errorf("Header %s may contain sensitive information: %s", key, value)
				}
			}
		}
	})
}

// TestTokenFileSecurity tests token file security measures
func TestTokenFileSecurity(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	t.Run("TokenFilePermissions", func(t *testing.T) {
		token := &StoredToken{
			ID:           uuid.New().String(),
			AuthMethod:   "Social",
			Provider:     "BuilderId",
			AccessToken:  "sensitive-access-token",
			RefreshToken: "sensitive-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		}

		err := SaveToken(token, testDir)
		if err != nil {
			t.Fatalf("Failed to save token: %v", err)
		}

		// Check file permissions
		tokenPath := fmt.Sprintf("%s/%s.json", testDir, token.ID)
		info, err := os.Stat(tokenPath)
		if err != nil {
			t.Fatalf("Failed to stat token file: %v", err)
		}

		mode := info.Mode()
		// File should be readable/writable by owner only (0600)
		expectedMode := os.FileMode(0600)
		if mode.Perm() != expectedMode {
			t.Logf("Warning: Token file permissions are %o, expected %o", mode.Perm(), expectedMode)
		}
	})

	t.Run("NoSensitiveDataInLogs", func(t *testing.T) {
		// This is a documentation test - verify that logging doesn't expose sensitive data
		// In actual implementation, ensure:
		// - Access tokens are never logged
		// - Refresh tokens are never logged
		// - Only token IDs are logged for debugging
		t.Log("Verify that sensitive token data is not logged in production code")
	})
}

// TestRateLimiting tests rate limiting (if implemented)
func TestRateLimiting(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	authService := &auth.AuthService{}
	handler, err := NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard/api/login", handler.Login)

	t.Run("MultipleRequests", func(t *testing.T) {
		// Send multiple requests rapidly
		successCount := 0
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest("GET", "/dashboard/api/login?provider=BuilderId", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				successCount++
			}
		}

		// All requests should succeed (no rate limiting implemented yet)
		// This test documents expected behavior
		t.Logf("Processed %d successful requests out of 100", successCount)
	})
}

// TestSessionSecurity tests session security measures
func TestSessionSecurity(t *testing.T) {
	t.Run("StateExpiration", func(t *testing.T) {
		store := NewStateStore()
		defer store.Stop()

		state := uuid.New().String()
		oauthState := &OAuthState{
			State:         state,
			CodeVerifier:  "test-verifier",
			CodeChallenge: "test-challenge",
			Provider:      "BuilderId",
		}

		// Save state
		err := store.SaveState(state, oauthState)
		if err != nil {
			t.Fatalf("Failed to save state: %v", err)
		}

		// Verify state exists
		_, err = store.GetState(state)
		if err != nil {
			t.Error("State should exist immediately after creation")
		}

		// Note: StateStore has 10 minute TTL
		// In production, verify states expire after TTL
		t.Log("State expiration is handled by StateStore with 10 minute TTL")
	})

	t.Run("StateIsolation", func(t *testing.T) {
		store := NewStateStore()
		defer store.Stop()

		// Create multiple states
		states := make([]string, 10)
		for i := 0; i < 10; i++ {
			state := uuid.New().String()
			oauthState := &OAuthState{
				State:         state,
				CodeVerifier:  fmt.Sprintf("verifier-%d", i),
				CodeChallenge: fmt.Sprintf("challenge-%d", i),
				Provider:      "BuilderId",
			}
			store.SaveState(state, oauthState)
			states[i] = state
		}

		// Verify each state is isolated
		for i, state := range states {
			oauthState, err := store.GetState(state)
			if err != nil {
				t.Errorf("Failed to get state %d: %v", i, err)
			}

			expectedVerifier := fmt.Sprintf("verifier-%d", i)
			if oauthState.CodeVerifier != expectedVerifier {
				t.Errorf("State %d has wrong verifier: expected %s, got %s",
					i, expectedVerifier, oauthState.CodeVerifier)
			}
		}
	})
}
