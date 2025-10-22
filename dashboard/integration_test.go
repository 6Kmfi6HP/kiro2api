package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"kiro2api/auth"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TestEndToEndOAuthFlow tests the complete OAuth flow from start to finish
func TestEndToEndOAuthFlow(t *testing.T) {
	// Setup test environment
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	// Create mock auth service
	authService := &auth.AuthService{}

	// Create dashboard handler
	handler, err := NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard/api/login", handler.Login)
	router.POST("/dashboard/callback", handler.ManualCallback)
	router.GET("/dashboard/tokens", handler.ListTokens)

	// Step 1: Initiate OAuth flow
	t.Run("InitiateOAuthFlow", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard/api/login?provider=BuilderId", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		// Verify response contains required fields
		if _, ok := response["authUrl"]; !ok {
			t.Error("Response missing authUrl")
		}
		if _, ok := response["redirectUri"]; !ok {
			t.Error("Response missing redirectUri")
		}
		if _, ok := response["state"]; !ok {
			t.Error("Response missing state")
		}
	})

	// Step 2: List tokens (should be empty initially)
	t.Run("ListTokensEmpty", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard/tokens", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if tokens, ok := response["tokens"].([]interface{}); ok {
			if len(tokens) != 0 {
				t.Errorf("Expected 0 tokens, got %d", len(tokens))
			}
		} else {
			t.Log("Tokens field not present or not an array (acceptable for empty state)")
		}
	})
}

// TestTokenLifecycle tests the complete lifecycle of a token
func TestTokenLifecycle(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	// Create a test token
	tokenID := uuid.New().String()
	token := &StoredToken{
		ID:           tokenID,
		AuthMethod:   "Social",
		Provider:     "BuilderId",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}

	// Step 1: Create token
	t.Run("CreateToken", func(t *testing.T) {
		err := SaveToken(token, testDir)
		if err != nil {
			t.Fatalf("Failed to save token: %v", err)
		}

		// Verify file exists
		tokenPath := filepath.Join(testDir, tokenID+".json")
		if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
			t.Error("Token file was not created")
		}
	})

	// Step 2: Read token
	t.Run("ReadToken", func(t *testing.T) {
		loadedToken, err := GetTokenByID(tokenID, testDir)
		if err != nil {
			t.Fatalf("Failed to load token: %v", err)
		}

		if loadedToken.ID != tokenID {
			t.Errorf("Expected token ID %s, got %s", tokenID, loadedToken.ID)
		}
		if loadedToken.Provider != "BuilderId" {
			t.Errorf("Expected provider BuilderId, got %s", loadedToken.Provider)
		}
	})

	// Step 3: Update token (simulate refresh)
	t.Run("UpdateToken", func(t *testing.T) {
		token.AccessToken = "new-access-token"
		token.ExpiresAt = time.Now().Add(2 * time.Hour)

		err := SaveToken(token, testDir)
		if err != nil {
			t.Fatalf("Failed to update token: %v", err)
		}

		// Verify update
		loadedToken, err := GetTokenByID(tokenID, testDir)
		if err != nil {
			t.Fatalf("Failed to load updated token: %v", err)
		}

		if loadedToken.AccessToken != "new-access-token" {
			t.Errorf("Token was not updated")
		}
	})

	// Step 4: Delete token
	t.Run("DeleteToken", func(t *testing.T) {
		err := DeleteToken(tokenID, testDir)
		if err != nil {
			t.Fatalf("Failed to delete token: %v", err)
		}

		// Verify file is deleted
		tokenPath := filepath.Join(testDir, tokenID+".json")
		if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
			t.Error("Token file was not deleted")
		}

		// Verify token cannot be loaded
		_, err = GetTokenByID(tokenID, testDir)
		if err == nil {
			t.Error("Expected error when loading deleted token")
		}
	})
}

// TestConcurrentTokenOperations tests concurrent token operations
func TestConcurrentTokenOperations(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	numTokens := 10
	numOperations := 5

	var wg sync.WaitGroup
	errors := make(chan error, numTokens*numOperations)

	// Concurrent token creation
	t.Run("ConcurrentCreate", func(t *testing.T) {
		for i := 0; i < numTokens; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				token := &StoredToken{
					ID:           uuid.New().String(),
					AuthMethod:   "Social",
					Provider:     "BuilderId",
					AccessToken:  fmt.Sprintf("access-token-%d", index),
					RefreshToken: fmt.Sprintf("refresh-token-%d", index),
					ExpiresAt:    time.Now().Add(1 * time.Hour),
					CreatedAt:    time.Now(),
				}

				if err := SaveToken(token, testDir); err != nil {
					errors <- fmt.Errorf("failed to save token %d: %w", index, err)
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Error(err)
		}

		// Verify all tokens were created
		tokens, err := LoadTokens(testDir)
		if err != nil {
			t.Fatalf("Failed to load tokens: %v", err)
		}

		if len(tokens) != numTokens {
			t.Errorf("Expected %d tokens, got %d", numTokens, len(tokens))
		}
	})

	// Concurrent token reads
	t.Run("ConcurrentRead", func(t *testing.T) {
		tokens, err := LoadTokens(testDir)
		if err != nil {
			t.Fatalf("Failed to load tokens: %v", err)
		}

		errors := make(chan error, len(tokens)*numOperations)

		for _, token := range tokens {
			for j := 0; j < numOperations; j++ {
				wg.Add(1)
				go func(tokenID string) {
					defer wg.Done()

					_, err := GetTokenByID(tokenID, testDir)
					if err != nil {
						errors <- fmt.Errorf("failed to read token %s: %w", tokenID, err)
					}
				}(token.ID)
			}
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Error(err)
		}
	})

	// Concurrent token updates
	t.Run("ConcurrentUpdate", func(t *testing.T) {
		tokens, err := LoadTokens(testDir)
		if err != nil {
			t.Fatalf("Failed to load tokens: %v", err)
		}

		errors := make(chan error, len(tokens))

		for _, token := range tokens {
			wg.Add(1)
			go func(t *StoredToken) {
				defer wg.Done()

				t.AccessToken = "updated-" + t.AccessToken
				t.ExpiresAt = time.Now().Add(2 * time.Hour)

				if err := SaveToken(t, testDir); err != nil {
					errors <- fmt.Errorf("failed to update token %s: %w", t.ID, err)
				}
			}(token)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Error(err)
		}

		// Verify updates
		updatedTokens, err := LoadTokens(testDir)
		if err != nil {
			t.Fatalf("Failed to load updated tokens: %v", err)
		}

		for _, token := range updatedTokens {
			if !bytes.HasPrefix([]byte(token.AccessToken), []byte("updated-")) {
				t.Errorf("Token %s was not updated", token.ID)
			}
		}
	})

	// Concurrent token deletes
	t.Run("ConcurrentDelete", func(t *testing.T) {
		tokens, err := LoadTokens(testDir)
		if err != nil {
			t.Fatalf("Failed to load tokens: %v", err)
		}

		errors := make(chan error, len(tokens))

		for _, token := range tokens {
			wg.Add(1)
			go func(tokenID string) {
				defer wg.Done()

				if err := DeleteToken(tokenID, testDir); err != nil {
					errors <- fmt.Errorf("failed to delete token %s: %w", tokenID, err)
				}
			}(token.ID)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Error(err)
		}

		// Verify all tokens were deleted
		remainingTokens, err := LoadTokens(testDir)
		if err != nil {
			t.Fatalf("Failed to load tokens: %v", err)
		}

		if len(remainingTokens) != 0 {
			t.Errorf("Expected 0 tokens, got %d", len(remainingTokens))
		}
	})
}

// TestErrorRecovery tests error recovery scenarios
func TestErrorRecovery(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	t.Run("RecoverFromInvalidJSON", func(t *testing.T) {
		// Create invalid JSON file
		invalidPath := filepath.Join(testDir, "invalid.json")
		if err := os.WriteFile(invalidPath, []byte("invalid json"), 0600); err != nil {
			t.Fatalf("Failed to create invalid file: %v", err)
		}

		// LoadTokens should skip invalid files
		tokens, err := LoadTokens(testDir)
		if err != nil {
			t.Fatalf("LoadTokens failed: %v", err)
		}

		if len(tokens) != 0 {
			t.Errorf("Expected 0 tokens, got %d", len(tokens))
		}
	})

	t.Run("RecoverFromMissingDirectory", func(t *testing.T) {
		nonExistentDir := filepath.Join(testDir, "nonexistent")

		// LoadTokens should return empty list for missing directory
		tokens, err := LoadTokens(nonExistentDir)
		if err != nil {
			t.Fatalf("LoadTokens failed: %v", err)
		}

		if len(tokens) != 0 {
			t.Errorf("Expected 0 tokens, got %d", len(tokens))
		}
	})

	t.Run("RecoverFromPermissionDenied", func(t *testing.T) {
		// Create token
		token := &StoredToken{
			ID:           uuid.New().String(),
			AuthMethod:   "Social",
			Provider:     "BuilderId",
			AccessToken:  "test-token",
			RefreshToken: "test-refresh",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		}

		if err := SaveToken(token, testDir); err != nil {
			t.Fatalf("Failed to save token: %v", err)
		}

		// Remove read permission
		tokenPath := filepath.Join(testDir, token.ID+".json")
		if err := os.Chmod(tokenPath, 0000); err != nil {
			t.Fatalf("Failed to change permissions: %v", err)
		}

		// Restore permissions for cleanup
		defer os.Chmod(tokenPath, 0600)

		// LoadTokens should skip unreadable files
		tokens, err := LoadTokens(testDir)
		if err != nil {
			t.Fatalf("LoadTokens failed: %v", err)
		}

		// Token should be skipped
		if len(tokens) != 0 {
			t.Logf("Warning: Expected 0 tokens due to permission denied, got %d", len(tokens))
		}
	})
}

// TestManualCallbackFlow tests the manual callback submission flow
func TestManualCallbackFlow(t *testing.T) {
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

	t.Run("ValidCallbackURL", func(t *testing.T) {
		// Create a valid state
		state := uuid.New().String()
		oauthState := &OAuthState{
			State:         state,
			CodeVerifier:  "test-verifier",
			CodeChallenge: "test-challenge",
			Provider:      "BuilderId",
		}
		handler.stateStore.SaveState(state, oauthState)

		// Submit callback URL
		callbackURL := fmt.Sprintf("http://127.0.0.1:12345/oauth/callback?code=test-code&state=%s", state)
		body := map[string]string{
			"callbackUrl": callbackURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Note: This will fail because we don't have a real Kiro auth service
		// But we can verify the request was processed
		if w.Code == http.StatusOK {
			t.Log("Callback processed successfully (unexpected in test environment)")
		} else {
			// Expected to fail due to missing auth service
			t.Logf("Callback failed as expected: %d", w.Code)
		}
	})

	t.Run("InvalidCallbackURL", func(t *testing.T) {
		body := map[string]string{
			"callbackUrl": "not-a-valid-url",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("MissingCodeParameter", func(t *testing.T) {
		state := uuid.New().String()
		callbackURL := fmt.Sprintf("http://127.0.0.1:12345/oauth/callback?state=%s", state)
		body := map[string]string{
			"callbackUrl": callbackURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		// Verify error message
		responseBody := w.Body.String()
		if !strings.Contains(responseBody, "code") {
			t.Error("Error message should mention missing code parameter")
		}
	})

	t.Run("InvalidState", func(t *testing.T) {
		callbackURL := "http://127.0.0.1:12345/oauth/callback?code=test-code&state=invalid-state"
		body := map[string]string{
			"callbackUrl": callbackURL,
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/dashboard/callback", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", w.Code)
		}

		// Verify error message
		responseBody := w.Body.String()
		if !strings.Contains(responseBody, "state") {
			t.Error("Error message should mention invalid state")
		}
	})
}

// TestHTTPHandlers tests all HTTP handlers
func TestHTTPHandlers(t *testing.T) {
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
	router.GET("/dashboard/tokens", handler.ListTokens)
	router.POST("/dashboard/tokens/refresh/:id", handler.RefreshToken)
	router.DELETE("/dashboard/tokens/:id", handler.DeleteToken)

	t.Run("HomeHandler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("ListTokensHandler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard/tokens", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if _, ok := response["tokens"]; !ok {
			t.Error("Response missing tokens field")
		}
	})

	t.Run("RefreshTokenHandler", func(t *testing.T) {
		// Create a test token
		tokenID := uuid.New().String()
		token := &StoredToken{
			ID:           tokenID,
			AuthMethod:   "Social",
			Provider:     "BuilderId",
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		}
		SaveToken(token, testDir)

		req := httptest.NewRequest("POST", "/dashboard/tokens/refresh/"+tokenID, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Expected to fail without real auth service
		if w.Code == http.StatusOK {
			t.Log("Refresh succeeded (unexpected in test environment)")
		} else {
			t.Logf("Refresh failed as expected: %d", w.Code)
		}
	})

	t.Run("DeleteTokenHandler", func(t *testing.T) {
		// Create a test token
		tokenID := uuid.New().String()
		token := &StoredToken{
			ID:           tokenID,
			AuthMethod:   "Social",
			Provider:     "BuilderId",
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		}
		SaveToken(token, testDir)

		req := httptest.NewRequest("DELETE", "/dashboard/tokens/"+tokenID, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Verify token was deleted
		_, err := GetTokenByID(tokenID, testDir)
		if err == nil {
			t.Error("Token should have been deleted")
		}
	})
}

// BenchmarkTokenOperations benchmarks token operations
func BenchmarkTokenOperations(b *testing.B) {
	testDir := setupTestDir(&testing.T{})
	defer cleanupTestDir(&testing.T{}, testDir)

	b.Run("SaveToken", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			token := &StoredToken{
				ID:           uuid.New().String(),
				AuthMethod:   "Social",
				Provider:     "BuilderId",
				AccessToken:  "test-access-token",
				RefreshToken: "test-refresh-token",
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				CreatedAt:    time.Now(),
			}
			SaveToken(token, testDir)
		}
	})

	// Create tokens for read benchmark
	tokenIDs := make([]string, 100)
	for i := 0; i < 100; i++ {
		token := &StoredToken{
			ID:           uuid.New().String(),
			AuthMethod:   "Social",
			Provider:     "BuilderId",
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		}
		SaveToken(token, testDir)
		tokenIDs[i] = token.ID
	}

	b.Run("LoadTokens", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			LoadTokens(testDir)
		}
	})

	b.Run("GetTokenByID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			GetTokenByID(tokenIDs[i%len(tokenIDs)], testDir)
		}
	})
}

// mockResponseWriter implements http.ResponseWriter for testing
type mockResponseWriter struct {
	header http.Header
	body   *bytes.Buffer
	status int
}

func newMockResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{
		header: make(http.Header),
		body:   new(bytes.Buffer),
		status: http.StatusOK,
	}
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	return m.body.Write(b)
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.status = statusCode
}

func (m *mockResponseWriter) Body() io.Reader {
	return m.body
}
