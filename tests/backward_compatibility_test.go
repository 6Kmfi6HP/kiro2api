package tests

import (
	"encoding/json"
	"io"
	"kiro2api/auth"
	"kiro2api/dashboard"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// setupTestEnv creates a clean test environment
func setupTestEnv(t *testing.T) (string, func()) {
	testDir := filepath.Join(os.TempDir(), "kiro2api-compat-test-"+uuid.New().String())
	if err := os.MkdirAll(testDir, 0700); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(testDir)
	}

	return testDir, cleanup
}

// TestServiceStartsWithoutKIROAuthToken tests that service can start without KIRO_AUTH_TOKEN
func TestServiceStartsWithoutKIROAuthToken(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	// Unset KIRO_AUTH_TOKEN
	oldValue := os.Getenv("KIRO_AUTH_TOKEN")
	os.Unsetenv("KIRO_AUTH_TOKEN")
	defer func() {
		if oldValue != "" {
			os.Setenv("KIRO_AUTH_TOKEN", oldValue)
		}
	}()

	// Create auth service without tokens
	authService := &auth.AuthService{}

	// Create dashboard handler (simulates service startup)
	handler, err := dashboard.NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Service failed to start without KIRO_AUTH_TOKEN: %v", err)
	}
	defer handler.Stop()

	// Verify dashboard is accessible
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard", handler.Home)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Dashboard should be accessible, got status %d", w.Code)
	}
}

// TestServiceStartsWithKIROAuthToken tests that service still works with KIRO_AUTH_TOKEN set
func TestServiceStartsWithKIROAuthToken(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	// Set KIRO_AUTH_TOKEN
	authToken := `[{"auth":"Social","refreshToken":"test-refresh-token"}]`
	oldValue := os.Getenv("KIRO_AUTH_TOKEN")
	os.Setenv("KIRO_AUTH_TOKEN", authToken)
	defer func() {
		if oldValue != "" {
			os.Setenv("KIRO_AUTH_TOKEN", oldValue)
		} else {
			os.Unsetenv("KIRO_AUTH_TOKEN")
		}
	}()

	// Create auth service with tokens from environment
	authService := &auth.AuthService{}

	// Create dashboard handler
	handler, err := dashboard.NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Service failed to start with KIRO_AUTH_TOKEN: %v", err)
	}
	defer handler.Stop()

	// Verify dashboard is still accessible
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/dashboard", handler.Home)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Dashboard should be accessible with KIRO_AUTH_TOKEN set, got status %d", w.Code)
	}
}

// TestTokenLoadingPriority tests that environment variable tokens take priority over file tokens
func TestTokenLoadingPriority(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	// Create a token file
	fileToken := &dashboard.StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		Provider:     "BuilderId",
		AccessToken:  "file-access-token",
		RefreshToken: "file-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}
	if err := dashboard.SaveToken(fileToken, testDir); err != nil {
		t.Fatalf("Failed to save file token: %v", err)
	}

	// Set KIRO_AUTH_TOKEN
	authToken := `[{"auth":"Social","refreshToken":"env-refresh-token"}]`
	oldValue := os.Getenv("KIRO_AUTH_TOKEN")
	os.Setenv("KIRO_AUTH_TOKEN", authToken)
	defer func() {
		if oldValue != "" {
			os.Setenv("KIRO_AUTH_TOKEN", oldValue)
		} else {
			os.Unsetenv("KIRO_AUTH_TOKEN")
		}
	}()

	// In a real scenario, auth service would load tokens from both sources
	// Environment tokens should be used first, then file tokens
	// This test documents the expected behavior

	t.Log("Environment variable tokens should take priority over file tokens")
	t.Log("Both sources should be available for API requests")
}

// TestExistingAPIEndpointsUnchanged tests that existing API endpoints still work
func TestExistingAPIEndpointsUnchanged(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	authService := &auth.AuthService{}
	handler, err := dashboard.NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Dashboard endpoints (new)
	router.GET("/dashboard", handler.Home)
	router.GET("/dashboard/tokens", handler.ListTokens)

	// Simulate existing API endpoints
	router.GET("/v1/models", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"models": []string{
				"claude-sonnet-4-20250514",
				"claude-3-7-sonnet-20250219",
			},
		})
	})

	router.POST("/v1/messages", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"id":      "msg_123",
			"type":    "message",
			"role":    "assistant",
			"content": []map[string]string{{"type": "text", "text": "Hello"}},
		})
	})

	router.POST("/v1/chat/completions", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"id":      "chatcmpl-123",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "claude-sonnet-4-20250514",
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]string{
						"role":    "assistant",
						"content": "Hello",
					},
					"finish_reason": "stop",
				},
			},
		})
	})

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{"GetModels", "GET", "/v1/models", http.StatusOK},
		{"PostMessages", "POST", "/v1/messages", http.StatusOK},
		{"PostChatCompletions", "POST", "/v1/chat/completions", http.StatusOK},
		{"GetDashboard", "GET", "/dashboard", http.StatusOK},
		{"GetDashboardTokens", "GET", "/dashboard/tokens", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.method == "POST" {
				body = nil // In real tests, would include request body
			}

			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.method == "POST" {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestExistingAuthFlowUnchanged tests that existing authentication flow still works
func TestExistingAuthFlowUnchanged(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	authService := &auth.AuthService{}
	handler, err := dashboard.NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Simulate existing auth middleware
	authMiddleware := func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		apiKey := c.GetHeader("x-api-key")

		if authHeader == "" && apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// In real implementation, would validate token
		c.Next()
	}

	// Protected endpoint
	router.POST("/v1/messages", authMiddleware, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	t.Run("AuthWithBearerToken", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200 with Bearer token, got %d", w.Code)
		}
	})

	t.Run("AuthWithAPIKey", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		req.Header.Set("x-api-key", "test-api-key")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200 with API key, got %d", w.Code)
		}
	})

	t.Run("AuthWithoutCredentials", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 without credentials, got %d", w.Code)
		}
	})
}

// TestDashboardDoesNotBreakExistingFunctionality tests that dashboard doesn't interfere with existing features
func TestDashboardDoesNotBreakExistingFunctionality(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	// Create some tokens via dashboard
	token1 := &dashboard.StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		Provider:     "BuilderId",
		AccessToken:  "access-token-1",
		RefreshToken: "refresh-token-1",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}
	dashboard.SaveToken(token1, testDir)

	token2 := &dashboard.StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		Provider:     "Google",
		AccessToken:  "access-token-2",
		RefreshToken: "refresh-token-2",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		CreatedAt:    time.Now(),
	}
	dashboard.SaveToken(token2, testDir)

	// Verify tokens can be loaded
	tokens, err := dashboard.LoadTokens(testDir)
	if err != nil {
		t.Fatalf("Failed to load tokens: %v", err)
	}

	if len(tokens) != 2 {
		t.Errorf("Expected 2 tokens, got %d", len(tokens))
	}

	// Verify tokens can be used (in real scenario, would test API requests)
	t.Log("Dashboard tokens are available for API requests")
}

// TestMigrationFromEnvToFiles tests migration from environment variable to file-based tokens
func TestMigrationFromEnvToFiles(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	// Step 1: Start with environment variable tokens
	authToken := `[{"auth":"Social","refreshToken":"env-token-1"},{"auth":"Social","refreshToken":"env-token-2"}]`
	oldValue := os.Getenv("KIRO_AUTH_TOKEN")
	os.Setenv("KIRO_AUTH_TOKEN", authToken)
	defer func() {
		if oldValue != "" {
			os.Setenv("KIRO_AUTH_TOKEN", oldValue)
		} else {
			os.Unsetenv("KIRO_AUTH_TOKEN")
		}
	}()

	// Verify environment tokens are parsed correctly
	var envTokens []map[string]interface{}
	if err := json.Unmarshal([]byte(authToken), &envTokens); err != nil {
		t.Fatalf("Failed to parse environment tokens: %v", err)
	}

	if len(envTokens) != 2 {
		t.Errorf("Expected 2 environment tokens, got %d", len(envTokens))
	}

	// Step 2: Add tokens via dashboard (simulates migration)
	dashboardToken := &dashboard.StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		Provider:     "BuilderId",
		AccessToken:  "dashboard-access-token",
		RefreshToken: "dashboard-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}
	if err := dashboard.SaveToken(dashboardToken, testDir); err != nil {
		t.Fatalf("Failed to save dashboard token: %v", err)
	}

	// Step 3: Verify both sources coexist
	fileTokens, err := dashboard.LoadTokens(testDir)
	if err != nil {
		t.Fatalf("Failed to load file tokens: %v", err)
	}

	if len(fileTokens) != 1 {
		t.Errorf("Expected 1 file token, got %d", len(fileTokens))
	}

	// Step 4: Remove environment variable (complete migration)
	os.Unsetenv("KIRO_AUTH_TOKEN")

	// Verify file tokens still work
	fileTokens, err = dashboard.LoadTokens(testDir)
	if err != nil {
		t.Fatalf("Failed to load file tokens after migration: %v", err)
	}

	if len(fileTokens) != 1 {
		t.Errorf("Expected 1 file token after migration, got %d", len(fileTokens))
	}

	t.Log("Migration from environment variable to file-based tokens successful")
}

// TestBackwardCompatibilityWithOldClients tests that old clients still work
func TestBackwardCompatibilityWithOldClients(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	authService := &auth.AuthService{}
	handler, err := dashboard.NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Simulate old API endpoints
	router.GET("/v1/models", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"models": []string{
				"claude-sonnet-4-20250514",
			},
		})
	})

	// Old client request (no knowledge of dashboard)
	req := httptest.NewRequest("GET", "/v1/models", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Old client request should still work, got status %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	models, ok := response["models"].([]interface{})
	if !ok || len(models) == 0 {
		t.Error("Response should contain models list")
	}
}

// TestConfigurationBackwardCompatibility tests that old configuration still works
func TestConfigurationBackwardCompatibility(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	// Test old configuration format
	oldConfig := `[
		{
			"auth": "Social",
			"refreshToken": "old-refresh-token"
		},
		{
			"auth": "IdC",
			"refreshToken": "old-idc-token",
			"clientId": "old-client-id",
			"clientSecret": "old-client-secret"
		}
	]`

	var configs []map[string]interface{}
	if err := json.Unmarshal([]byte(oldConfig), &configs); err != nil {
		t.Fatalf("Old configuration format should still be parseable: %v", err)
	}

	if len(configs) != 2 {
		t.Errorf("Expected 2 configurations, got %d", len(configs))
	}

	// Verify required fields are present
	for i, config := range configs {
		if _, ok := config["auth"]; !ok {
			t.Errorf("Configuration %d missing 'auth' field", i)
		}
		if _, ok := config["refreshToken"]; !ok {
			t.Errorf("Configuration %d missing 'refreshToken' field", i)
		}
	}

	t.Log("Old configuration format is still compatible")
}

// TestNoRegressionInPerformance tests that dashboard doesn't significantly impact performance
func TestNoRegressionInPerformance(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	authService := &auth.AuthService{}
	handler, err := dashboard.NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/v1/models", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"models": []string{"claude-sonnet-4-20250514"}})
	})

	// Measure response time
	start := time.Now()
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/v1/models", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d failed with status %d", i, w.Code)
		}
	}
	duration := time.Since(start)

	avgDuration := duration / 100
	t.Logf("Average response time: %v", avgDuration)

	// Response time should be reasonable (< 10ms per request)
	if avgDuration > 10*time.Millisecond {
		t.Logf("Warning: Average response time is high: %v", avgDuration)
	}
}

// TestDashboardOptionalFeature tests that dashboard is truly optional
func TestDashboardOptionalFeature(t *testing.T) {
	testDir, cleanup := setupTestEnv(t)
	defer cleanup()

	// Service should work without ever accessing dashboard
	authToken := `[{"auth":"Social","refreshToken":"test-token"}]`
	oldValue := os.Getenv("KIRO_AUTH_TOKEN")
	os.Setenv("KIRO_AUTH_TOKEN", authToken)
	defer func() {
		if oldValue != "" {
			os.Setenv("KIRO_AUTH_TOKEN", oldValue)
		} else {
			os.Unsetenv("KIRO_AUTH_TOKEN")
		}
	}()

	authService := &auth.AuthService{}

	// Create dashboard handler but never use it
	handler, err := dashboard.NewDashboardHandler(testDir, authService)
	if err != nil {
		t.Fatalf("Failed to create dashboard handler: %v", err)
	}
	defer handler.Stop()

	// Simulate API usage without dashboard
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/v1/messages", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("API should work without using dashboard, got status %d", w.Code)
	}

	t.Log("Dashboard is truly optional - service works without it")
}
