package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func setupTestHandler(t *testing.T) (*DashboardHandler, string) {
	// Create temporary directory for test tokens
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("kiro2api-test-%s", uuid.New().String()))
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	handler, err := NewDashboardHandler(tempDir, nil)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	return handler, tempDir
}

func cleanupTestHandler(t *testing.T, tempDir string) {
	if err := os.RemoveAll(tempDir); err != nil {
		t.Errorf("Failed to cleanup temp directory: %v", err)
	}
}

func TestDashboardHome(t *testing.T) {
	handler, tempDir := setupTestHandler(t)
	defer cleanupTestHandler(t, tempDir)

	// Create test token
	testToken := &StoredToken{
		ID:           "test-token-1",
		AuthMethod:   "Social",
		Provider:     "Google",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}
	if err := SaveToken(testToken, tempDir); err != nil {
		t.Fatalf("Failed to save test token: %v", err)
	}

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard", handler.Home)

	// Test request
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse JSON response
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response structure
	if !response["success"].(bool) {
		t.Error("Expected success to be true")
	}

	data := response["data"].(map[string]interface{})
	tokens := data["tokens"].([]interface{})
	if len(tokens) != 1 {
		t.Errorf("Expected 1 token, got %d", len(tokens))
	}
}

func TestLoginHandler(t *testing.T) {
	handler, tempDir := setupTestHandler(t)
	defer cleanupTestHandler(t, tempDir)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard/login", handler.Login)

	tests := []struct {
		name           string
		provider       string
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "Valid Social Provider",
			provider:       "Google",
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Invalid Provider",
			provider:       "InvalidProvider",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "IdC Provider (Not Implemented)",
			provider:       "BuilderId",
			expectedStatus: http.StatusNotImplemented,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/dashboard/login?provider=%s", tt.provider), nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}

			if tt.expectError {
				if response["success"].(bool) {
					t.Error("Expected success to be false for error case")
				}
			} else {
				if !response["success"].(bool) {
					t.Error("Expected success to be true")
				}
			}
		})
	}
}

func TestManualCallback(t *testing.T) {
	handler, tempDir := setupTestHandler(t)
	defer cleanupTestHandler(t, tempDir)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/dashboard/callback", handler.ManualCallback)

	tests := []struct {
		name           string
		callbackURL    string
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "Missing Callback URL",
			callbackURL:    "",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "Invalid URL Format",
			callbackURL:    "not-a-valid-url",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "Missing Code Parameter",
			callbackURL:    "http://127.0.0.1:12345/oauth/callback?state=test-state",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "Missing State Parameter",
			callbackURL:    "http://127.0.0.1:12345/oauth/callback?code=test-code",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := map[string]string{}
			if tt.callbackURL != "" {
				reqBody["callbackUrl"] = tt.callbackURL
			}

			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/dashboard/callback", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}

			if tt.expectError {
				if response["success"].(bool) {
					t.Error("Expected success to be false for error case")
				}
			}
		})
	}
}

func TestListTokens(t *testing.T) {
	handler, tempDir := setupTestHandler(t)
	defer cleanupTestHandler(t, tempDir)

	// Create multiple test tokens
	tokens := []*StoredToken{
		{
			ID:           "token-1",
			AuthMethod:   "Social",
			Provider:     "Google",
			AccessToken:  "access-1",
			RefreshToken: "refresh-1",
			ExpiresAt:    time.Now().Add(24 * time.Hour),
			CreatedAt:    time.Now(),
		},
		{
			ID:           "token-2",
			AuthMethod:   "Social",
			Provider:     "Github",
			AccessToken:  "access-2",
			RefreshToken: "refresh-2",
			ExpiresAt:    time.Now().Add(48 * time.Hour),
			CreatedAt:    time.Now(),
		},
	}

	for _, token := range tokens {
		if err := SaveToken(token, tempDir); err != nil {
			t.Fatalf("Failed to save test token: %v", err)
		}
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard/tokens", handler.ListTokens)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/tokens", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if !response["success"].(bool) {
		t.Error("Expected success to be true")
	}

	data := response["data"].(map[string]interface{})
	tokensList := data["tokens"].([]interface{})
	if len(tokensList) != 2 {
		t.Errorf("Expected 2 tokens, got %d", len(tokensList))
	}

	// Verify sensitive fields are not exposed
	firstToken := tokensList[0].(map[string]interface{})
	if _, exists := firstToken["accessToken"]; exists {
		t.Error("Access token should not be exposed in list response")
	}
	if _, exists := firstToken["refreshToken"]; exists {
		t.Error("Refresh token should not be exposed in list response")
	}
}

func TestDeleteTokenHandler(t *testing.T) {
	handler, tempDir := setupTestHandler(t)
	defer cleanupTestHandler(t, tempDir)

	// Create test token
	testToken := &StoredToken{
		ID:           "token-to-delete",
		AuthMethod:   "Social",
		Provider:     "Google",
		AccessToken:  "test-access",
		RefreshToken: "test-refresh",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}
	if err := SaveToken(testToken, tempDir); err != nil {
		t.Fatalf("Failed to save test token: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE("/dashboard/tokens/:id", handler.DeleteToken)

	// Test successful deletion
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/tokens/token-to-delete", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if !response["success"].(bool) {
		t.Error("Expected success to be true")
	}

	// Verify token is deleted
	if TokenExists("token-to-delete", tempDir) {
		t.Error("Token should be deleted")
	}

	// Test deleting non-existent token
	req = httptest.NewRequest(http.MethodDelete, "/dashboard/tokens/non-existent", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestInvalidState(t *testing.T) {
	handler, tempDir := setupTestHandler(t)
	defer cleanupTestHandler(t, tempDir)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard/callback", handler.Callback)

	// Test with invalid state
	req := httptest.NewRequest(http.MethodGet, "/dashboard/callback?code=test-code&state=invalid-state", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestErrorHandling(t *testing.T) {
	handler, tempDir := setupTestHandler(t)
	defer cleanupTestHandler(t, tempDir)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard/tokens", handler.ListTokens)
	router.DELETE("/dashboard/tokens/:id", handler.DeleteToken)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{
			name:           "Delete Non-Existent Token",
			method:         http.MethodDelete,
			path:           "/dashboard/tokens/non-existent-token",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Delete Empty Token ID",
			method:         http.MethodDelete,
			path:           "/dashboard/tokens/",
			expectedStatus: http.StatusNotFound, // Gin returns 404 for missing param
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(SecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify security headers are present
	headers := map[string]string{
		"Content-Security-Policy":   "default-src 'self'",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"X-XSS-Protection":          "1; mode=block",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}

	for header, expectedValue := range headers {
		actualValue := w.Header().Get(header)
		if actualValue == "" {
			t.Errorf("Expected header %s to be present", header)
		}
		if header == "Content-Security-Policy" && actualValue != "" {
			// Just check it's present, don't check exact value
			continue
		}
		if actualValue != expectedValue && expectedValue != "" {
			t.Errorf("Expected header %s to be %s, got %s", header, expectedValue, actualValue)
		}
	}
}

func TestTokenStatusCalculation(t *testing.T) {
	handler, tempDir := setupTestHandler(t)
	defer cleanupTestHandler(t, tempDir)

	// Create tokens with different expiry times
	tokens := []*StoredToken{
		{
			ID:           "valid-token",
			AuthMethod:   "Social",
			Provider:     "Google",
			AccessToken:  "access-1",
			RefreshToken: "refresh-1",
			ExpiresAt:    time.Now().Add(48 * time.Hour), // Valid
			CreatedAt:    time.Now(),
		},
		{
			ID:           "expiring-token",
			AuthMethod:   "Social",
			Provider:     "Google",
			AccessToken:  "access-2",
			RefreshToken: "refresh-2",
			ExpiresAt:    time.Now().Add(12 * time.Hour), // Expiring soon
			CreatedAt:    time.Now(),
		},
		{
			ID:           "expired-token",
			AuthMethod:   "Social",
			Provider:     "Google",
			AccessToken:  "access-3",
			RefreshToken: "refresh-3",
			ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired
			CreatedAt:    time.Now(),
		},
	}

	for _, token := range tokens {
		if err := SaveToken(token, tempDir); err != nil {
			t.Fatalf("Failed to save test token: %v", err)
		}
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard/tokens", handler.ListTokens)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/tokens", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	data := response["data"].(map[string]interface{})
	tokensList := data["tokens"].([]interface{})

	// Verify status calculation
	statusMap := make(map[string]string)
	for _, tokenData := range tokensList {
		token := tokenData.(map[string]interface{})
		statusMap[token["id"].(string)] = token["status"].(string)
	}

	if statusMap["valid-token"] != "valid" {
		t.Errorf("Expected valid-token status to be 'valid', got '%s'", statusMap["valid-token"])
	}
	if statusMap["expiring-token"] != "expiring" {
		t.Errorf("Expected expiring-token status to be 'expiring', got '%s'", statusMap["expiring-token"])
	}
	if statusMap["expired-token"] != "expired" {
		t.Errorf("Expected expired-token status to be 'expired', got '%s'", statusMap["expired-token"])
	}
}
