package dashboard

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// setupTestDir creates a temporary directory for testing
func setupTestDir(t *testing.T) string {
	dir := filepath.Join(os.TempDir(), "kiro2api-test-"+uuid.New().String())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	return dir
}

// cleanupTestDir removes the test directory
func cleanupTestDir(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Errorf("Failed to cleanup test directory: %v", err)
	}
}

// TestSaveToken tests saving a token to filesystem
func TestSaveToken(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	token := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		Provider:     "BuilderId",
		RefreshToken: "test-refresh-token",
		AccessToken:  "test-access-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
		Region:       "us-east-1",
		Metadata: map[string]string{
			"source": "test",
		},
	}

	// Save token
	err := SaveToken(token, testDir)
	if err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Verify file exists
	filename := filepath.Join(testDir, token.ID+".json")
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Errorf("Token file was not created: %s", filename)
	}

	// Verify file permissions (on Unix-like systems)
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("Failed to stat token file: %v", err)
	}

	// Check permissions are restrictive (owner read/write only)
	mode := info.Mode()
	if mode.Perm() != TokenFilePermissions {
		t.Logf("Warning: File permissions are %v, expected %v", mode.Perm(), TokenFilePermissions)
	}
}

// TestSaveTokenValidation tests token validation
func TestSaveTokenValidation(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	tests := []struct {
		name      string
		token     *StoredToken
		wantError bool
	}{
		{
			name: "valid token",
			token: &StoredToken{
				ID:           uuid.New().String(),
				AuthMethod:   "Social",
				RefreshToken: "test-token",
			},
			wantError: false,
		},
		{
			name: "missing ID",
			token: &StoredToken{
				AuthMethod:   "Social",
				RefreshToken: "test-token",
			},
			wantError: true,
		},
		{
			name: "missing refresh token",
			token: &StoredToken{
				ID:         uuid.New().String(),
				AuthMethod: "Social",
			},
			wantError: true,
		},
		{
			name: "missing auth method",
			token: &StoredToken{
				ID:           uuid.New().String(),
				RefreshToken: "test-token",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SaveToken(tt.token, testDir)
			if (err != nil) != tt.wantError {
				t.Errorf("SaveToken() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestLoadTokens tests loading tokens from directory
func TestLoadTokens(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	// Create test tokens
	tokens := []*StoredToken{
		{
			ID:           uuid.New().String(),
			AuthMethod:   "Social",
			Provider:     "BuilderId",
			RefreshToken: "token1",
			CreatedAt:    time.Now(),
		},
		{
			ID:           uuid.New().String(),
			AuthMethod:   "IdC",
			Provider:     "Enterprise",
			RefreshToken: "token2",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			CreatedAt:    time.Now(),
		},
	}

	// Save tokens
	for _, token := range tokens {
		if err := SaveToken(token, testDir); err != nil {
			t.Fatalf("Failed to save token: %v", err)
		}
	}

	// Load tokens
	loadedTokens, err := LoadTokens(testDir)
	if err != nil {
		t.Fatalf("LoadTokens failed: %v", err)
	}

	// Verify count
	if len(loadedTokens) != len(tokens) {
		t.Errorf("Expected %d tokens, got %d", len(tokens), len(loadedTokens))
	}

	// Verify token IDs
	loadedIDs := make(map[string]bool)
	for _, token := range loadedTokens {
		loadedIDs[token.ID] = true
	}

	for _, token := range tokens {
		if !loadedIDs[token.ID] {
			t.Errorf("Token ID %s not found in loaded tokens", token.ID)
		}
	}
}

// TestLoadTokensEmptyDirectory tests loading from empty directory
func TestLoadTokensEmptyDirectory(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	tokens, err := LoadTokens(testDir)
	if err != nil {
		t.Fatalf("LoadTokens failed: %v", err)
	}

	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens, got %d", len(tokens))
	}
}

// TestLoadTokensNonexistentDirectory tests loading from nonexistent directory
func TestLoadTokensNonexistentDirectory(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "nonexistent-"+uuid.New().String())

	tokens, err := LoadTokens(testDir)
	if err != nil {
		t.Fatalf("LoadTokens failed: %v", err)
	}

	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens, got %d", len(tokens))
	}
}

// TestDeleteToken tests deleting a token
func TestDeleteToken(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	token := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		RefreshToken: "test-token",
	}

	// Save token
	if err := SaveToken(token, testDir); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Delete token
	if err := DeleteToken(token.ID, testDir); err != nil {
		t.Fatalf("DeleteToken failed: %v", err)
	}

	// Verify file is deleted
	filename := filepath.Join(testDir, token.ID+".json")
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		t.Errorf("Token file still exists after deletion: %s", filename)
	}
}

// TestDeleteTokenNonexistent tests deleting a nonexistent token
func TestDeleteTokenNonexistent(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	err := DeleteToken("nonexistent-id", testDir)
	if err == nil {
		t.Error("Expected error when deleting nonexistent token, got nil")
	}
}

// TestGetTokenByID tests retrieving a specific token
func TestGetTokenByID(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	token := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		Provider:     "BuilderId",
		RefreshToken: "test-token",
		CreatedAt:    time.Now(),
	}

	// Save token
	if err := SaveToken(token, testDir); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Get token by ID
	loadedToken, err := GetTokenByID(token.ID, testDir)
	if err != nil {
		t.Fatalf("GetTokenByID failed: %v", err)
	}

	// Verify token data
	if loadedToken.ID != token.ID {
		t.Errorf("Expected ID %s, got %s", token.ID, loadedToken.ID)
	}
	if loadedToken.RefreshToken != token.RefreshToken {
		t.Errorf("Expected refresh token %s, got %s", token.RefreshToken, loadedToken.RefreshToken)
	}
}

// TestListTokenIDs tests listing token IDs
func TestListTokenIDs(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	// Create test tokens
	tokenIDs := []string{
		uuid.New().String(),
		uuid.New().String(),
		uuid.New().String(),
	}

	for _, id := range tokenIDs {
		token := &StoredToken{
			ID:           id,
			AuthMethod:   "Social",
			RefreshToken: "test-token",
		}
		if err := SaveToken(token, testDir); err != nil {
			t.Fatalf("SaveToken failed: %v", err)
		}
	}

	// List token IDs
	listedIDs, err := ListTokenIDs(testDir)
	if err != nil {
		t.Fatalf("ListTokenIDs failed: %v", err)
	}

	// Verify count
	if len(listedIDs) != len(tokenIDs) {
		t.Errorf("Expected %d token IDs, got %d", len(tokenIDs), len(listedIDs))
	}

	// Verify IDs
	listedIDMap := make(map[string]bool)
	for _, id := range listedIDs {
		listedIDMap[id] = true
	}

	for _, id := range tokenIDs {
		if !listedIDMap[id] {
			t.Errorf("Token ID %s not found in listed IDs", id)
		}
	}
}

// TestTokenExists tests checking if a token exists
func TestTokenExists(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	token := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		RefreshToken: "test-token",
	}

	// Token should not exist initially
	if TokenExists(token.ID, testDir) {
		t.Error("Token should not exist before saving")
	}

	// Save token
	if err := SaveToken(token, testDir); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Token should exist now
	if !TokenExists(token.ID, testDir) {
		t.Error("Token should exist after saving")
	}

	// Delete token
	if err := DeleteToken(token.ID, testDir); err != nil {
		t.Fatalf("DeleteToken failed: %v", err)
	}

	// Token should not exist after deletion
	if TokenExists(token.ID, testDir) {
		t.Error("Token should not exist after deletion")
	}
}

// TestConcurrentSaveToken tests concurrent token saves
func TestConcurrentSaveToken(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			token := &StoredToken{
				ID:           uuid.New().String(),
				AuthMethod:   "Social",
				RefreshToken: "test-token",
			}

			if err := SaveToken(token, testDir); err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent save error: %v", err)
	}

	// Verify all tokens were saved
	tokens, err := LoadTokens(testDir)
	if err != nil {
		t.Fatalf("LoadTokens failed: %v", err)
	}

	if len(tokens) != numGoroutines {
		t.Errorf("Expected %d tokens, got %d", numGoroutines, len(tokens))
	}
}

// TestConcurrentLoadTokens tests concurrent token loads
func TestConcurrentLoadTokens(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	// Create test tokens
	for i := 0; i < 5; i++ {
		token := &StoredToken{
			ID:           uuid.New().String(),
			AuthMethod:   "Social",
			RefreshToken: "test-token",
		}
		if err := SaveToken(token, testDir); err != nil {
			t.Fatalf("SaveToken failed: %v", err)
		}
	}

	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := LoadTokens(testDir)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent load error: %v", err)
	}
}

// TestCleanupExpiredTokens tests cleaning up expired tokens
func TestCleanupExpiredTokens(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	// Create expired token
	expiredToken := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		RefreshToken: "expired-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	// Create valid token
	validToken := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		RefreshToken: "valid-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour), // Expires in 1 hour
	}

	// Create token without expiration
	noExpiryToken := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		RefreshToken: "no-expiry-token",
		// ExpiresAt is zero value
	}

	// Save all tokens
	if err := SaveToken(expiredToken, testDir); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}
	if err := SaveToken(validToken, testDir); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}
	if err := SaveToken(noExpiryToken, testDir); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Cleanup expired tokens
	deletedCount, err := CleanupExpiredTokens(testDir)
	if err != nil {
		t.Fatalf("CleanupExpiredTokens failed: %v", err)
	}

	// Should have deleted 1 token
	if deletedCount != 1 {
		t.Errorf("Expected 1 deleted token, got %d", deletedCount)
	}

	// Verify expired token is deleted
	if TokenExists(expiredToken.ID, testDir) {
		t.Error("Expired token should be deleted")
	}

	// Verify valid token still exists
	if !TokenExists(validToken.ID, testDir) {
		t.Error("Valid token should still exist")
	}

	// Verify token without expiry still exists
	if !TokenExists(noExpiryToken.ID, testDir) {
		t.Error("Token without expiry should still exist")
	}
}

// TestValidateTokensDirectory tests directory validation
func TestValidateTokensDirectory(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	// Should succeed for existing directory
	if err := ValidateTokensDirectory(testDir); err != nil {
		t.Errorf("ValidateTokensDirectory failed: %v", err)
	}

	// Should create directory if it doesn't exist
	newDir := filepath.Join(testDir, "new-tokens")
	if err := ValidateTokensDirectory(newDir); err != nil {
		t.Errorf("ValidateTokensDirectory failed to create directory: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		t.Error("Directory was not created")
	}
}

// TestAtomicWrite tests that token writes are atomic
func TestAtomicWrite(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	token := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "Social",
		RefreshToken: "test-token",
	}

	// Save token
	if err := SaveToken(token, testDir); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Verify no .tmp files remain
	entries, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Errorf("Temporary file should not exist: %s", entry.Name())
		}
	}
}

// TestIdCTokenValidation tests IdC token validation
func TestIdCTokenValidation(t *testing.T) {
	testDir := setupTestDir(t)
	defer cleanupTestDir(t, testDir)

	// Valid IdC token
	validIdCToken := &StoredToken{
		ID:           uuid.New().String(),
		AuthMethod:   "IdC",
		RefreshToken: "test-token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	if err := SaveToken(validIdCToken, testDir); err != nil {
		t.Fatalf("SaveToken failed for valid IdC token: %v", err)
	}

	// Load and verify
	loadedToken, err := GetTokenByID(validIdCToken.ID, testDir)
	if err != nil {
		t.Fatalf("GetTokenByID failed: %v", err)
	}

	if loadedToken.ClientID != validIdCToken.ClientID {
		t.Errorf("Expected ClientID %s, got %s", validIdCToken.ClientID, loadedToken.ClientID)
	}
	if loadedToken.ClientSecret != validIdCToken.ClientSecret {
		t.Errorf("Expected ClientSecret %s, got %s", validIdCToken.ClientSecret, loadedToken.ClientSecret)
	}
}
