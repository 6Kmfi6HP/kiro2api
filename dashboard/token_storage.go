package dashboard

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"kiro2api/logger"
)

// StoredToken represents a token stored in the filesystem
type StoredToken struct {
	ID           string            `json:"id"`
	AuthMethod   string            `json:"authMethod"`   // "Social" or "IdC"
	Provider     string            `json:"provider"`     // "BuilderId", "Enterprise", etc.
	AccessToken  string            `json:"accessToken"`
	RefreshToken string            `json:"refreshToken"`
	ExpiresAt    time.Time         `json:"expiresAt"`
	CreatedAt    time.Time         `json:"createdAt"`
	Region       string            `json:"region"`
	ClientID     string            `json:"clientId,omitempty"`     // For IdC auth
	ClientSecret string            `json:"clientSecret,omitempty"` // For IdC auth
	ClientIDHash string            `json:"clientIdHash,omitempty"`
	ProfileArn   string            `json:"profileArn,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

const (
	// DefaultTokensDir is the default directory for storing tokens
	DefaultTokensDir = "tokens"
	// TokenFilePermissions sets file permissions to read/write for owner only
	TokenFilePermissions = 0600
	// TokenDirPermissions sets directory permissions
	TokenDirPermissions = 0700
)

var (
	// fileLocks provides per-file locking for concurrent access
	fileLocks = make(map[string]*sync.Mutex)
	// fileLocksMutex protects the fileLocks map itself
	fileLocksMutex sync.Mutex
)

// getFileLock returns a mutex for the given file path
func getFileLock(path string) *sync.Mutex {
	fileLocksMutex.Lock()
	defer fileLocksMutex.Unlock()

	if lock, exists := fileLocks[path]; exists {
		return lock
	}

	lock := &sync.Mutex{}
	fileLocks[path] = lock
	return lock
}

// SaveToken writes a token to the filesystem as a JSON file
// The token is written atomically by first writing to a temp file, then renaming
func SaveToken(token *StoredToken, tokensDir string) error {
	if tokensDir == "" {
		tokensDir = DefaultTokensDir
	}

	// Validate token
	if token.ID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}
	if token.RefreshToken == "" {
		return fmt.Errorf("refresh token cannot be empty")
	}
	if token.AuthMethod == "" {
		return fmt.Errorf("auth method cannot be empty")
	}

	// Ensure tokens directory exists
	if err := os.MkdirAll(tokensDir, TokenDirPermissions); err != nil {
		return fmt.Errorf("failed to create tokens directory: %w", err)
	}

	// Construct file path
	filename := fmt.Sprintf("%s.json", token.ID)
	filePath := filepath.Join(tokensDir, filename)

	// Get file lock
	lock := getFileLock(filePath)
	lock.Lock()
	defer lock.Unlock()

	// Marshal token to JSON
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	// Write to temporary file first (atomic write)
	tempPath := filePath + ".tmp"
	if err := os.WriteFile(tempPath, data, TokenFilePermissions); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Rename temp file to final path (atomic operation)
	if err := os.Rename(tempPath, filePath); err != nil {
		// Clean up temp file on error
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	logger.Info("Token saved successfully",
		logger.String("token_id", token.ID),
		logger.String("auth_method", token.AuthMethod),
		logger.String("file_path", filePath))

	return nil
}

// LoadTokens reads all tokens from the tokens directory
func LoadTokens(tokensDir string) ([]*StoredToken, error) {
	if tokensDir == "" {
		tokensDir = DefaultTokensDir
	}

	// Check if directory exists
	if _, err := os.Stat(tokensDir); os.IsNotExist(err) {
		logger.Debug("Tokens directory does not exist", logger.String("dir", tokensDir))
		return []*StoredToken{}, nil
	}

	// Read directory entries
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read tokens directory: %w", err)
	}

	var tokens []*StoredToken
	var loadErrors []string

	for _, entry := range entries {
		// Skip directories and non-JSON files
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// Skip temporary files
		if filepath.Ext(entry.Name()) == ".tmp" {
			continue
		}

		filePath := filepath.Join(tokensDir, entry.Name())

		// Get file lock
		lock := getFileLock(filePath)
		lock.Lock()

		// Read and parse token file
		token, err := loadTokenFile(filePath)
		lock.Unlock()

		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", entry.Name(), err))
			logger.Warn("Failed to load token file",
				logger.String("file", entry.Name()),
				logger.Err(err))
			continue
		}

		tokens = append(tokens, token)
	}

	logger.Info("Loaded tokens from directory",
		logger.String("dir", tokensDir),
		logger.Int("count", len(tokens)),
		logger.Int("errors", len(loadErrors)))

	if len(loadErrors) > 0 {
		logger.Warn("Some token files failed to load",
			logger.Any("errors", loadErrors))
	}

	return tokens, nil
}

// loadTokenFile reads and parses a single token file
func loadTokenFile(filePath string) (*StoredToken, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse JSON
	var token StoredToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate required fields
	if token.ID == "" {
		return nil, fmt.Errorf("token ID is empty")
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("refresh token is empty")
	}
	if token.AuthMethod == "" {
		return nil, fmt.Errorf("auth method is empty")
	}

	// Validate IdC tokens have required fields
	if token.AuthMethod == "IdC" {
		if token.ClientID == "" || token.ClientSecret == "" {
			return nil, fmt.Errorf("IdC token missing clientId or clientSecret")
		}
	}

	return &token, nil
}

// DeleteToken removes a token file from the filesystem
func DeleteToken(tokenID string, tokensDir string) error {
	if tokensDir == "" {
		tokensDir = DefaultTokensDir
	}

	if tokenID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}

	// Construct file path
	filename := fmt.Sprintf("%s.json", tokenID)
	filePath := filepath.Join(tokensDir, filename)

	// Get file lock
	lock := getFileLock(filePath)
	lock.Lock()
	defer lock.Unlock()

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("token file does not exist: %s", tokenID)
	}

	// Delete file
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete token file: %w", err)
	}

	logger.Info("Token deleted successfully",
		logger.String("token_id", tokenID),
		logger.String("file_path", filePath))

	// Clean up file lock
	fileLocksMutex.Lock()
	delete(fileLocks, filePath)
	fileLocksMutex.Unlock()

	return nil
}

// GetTokenByID loads a specific token by ID
func GetTokenByID(tokenID string, tokensDir string) (*StoredToken, error) {
	if tokensDir == "" {
		tokensDir = DefaultTokensDir
	}

	if tokenID == "" {
		return nil, fmt.Errorf("token ID cannot be empty")
	}

	// Construct file path
	filename := fmt.Sprintf("%s.json", tokenID)
	filePath := filepath.Join(tokensDir, filename)

	// Get file lock
	lock := getFileLock(filePath)
	lock.Lock()
	defer lock.Unlock()

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("token not found: %s", tokenID)
	}

	// Load token
	return loadTokenFile(filePath)
}

// ListTokenIDs returns a list of all token IDs in the directory
func ListTokenIDs(tokensDir string) ([]string, error) {
	if tokensDir == "" {
		tokensDir = DefaultTokensDir
	}

	// Check if directory exists
	if _, err := os.Stat(tokensDir); os.IsNotExist(err) {
		return []string{}, nil
	}

	// Read directory entries
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read tokens directory: %w", err)
	}

	var tokenIDs []string
	for _, entry := range entries {
		// Skip directories and non-JSON files
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// Extract token ID from filename (remove .json extension)
		tokenID := entry.Name()[:len(entry.Name())-5]
		tokenIDs = append(tokenIDs, tokenID)
	}

	return tokenIDs, nil
}

// TokenExists checks if a token file exists
func TokenExists(tokenID string, tokensDir string) bool {
	if tokensDir == "" {
		tokensDir = DefaultTokensDir
	}

	filename := fmt.Sprintf("%s.json", tokenID)
	filePath := filepath.Join(tokensDir, filename)

	_, err := os.Stat(filePath)
	return err == nil
}

// CleanupExpiredTokens removes token files that have expired
func CleanupExpiredTokens(tokensDir string) (int, error) {
	tokens, err := LoadTokens(tokensDir)
	if err != nil {
		return 0, fmt.Errorf("failed to load tokens: %w", err)
	}

	deletedCount := 0
	now := time.Now()

	for _, token := range tokens {
		// Check if token is expired
		if !token.ExpiresAt.IsZero() && token.ExpiresAt.Before(now) {
			if err := DeleteToken(token.ID, tokensDir); err != nil {
				logger.Warn("Failed to delete expired token",
					logger.String("token_id", token.ID),
					logger.Err(err))
				continue
			}
			deletedCount++
		}
	}

	if deletedCount > 0 {
		logger.Info("Cleaned up expired tokens",
			logger.Int("deleted_count", deletedCount))
	}

	return deletedCount, nil
}

// ValidateTokensDirectory checks if the tokens directory is properly configured
func ValidateTokensDirectory(tokensDir string) error {
	if tokensDir == "" {
		tokensDir = DefaultTokensDir
	}

	// Check if directory exists
	info, err := os.Stat(tokensDir)
	if os.IsNotExist(err) {
		// Directory doesn't exist, try to create it
		if err := os.MkdirAll(tokensDir, TokenDirPermissions); err != nil {
			return fmt.Errorf("failed to create tokens directory: %w", err)
		}
		logger.Info("Created tokens directory", logger.String("dir", tokensDir))
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to stat tokens directory: %w", err)
	}

	// Check if it's a directory
	if !info.IsDir() {
		return fmt.Errorf("tokens path exists but is not a directory: %s", tokensDir)
	}

	// Check permissions (on Unix-like systems)
	mode := info.Mode()
	if mode.Perm()&fs.FileMode(0077) != 0 {
		logger.Warn("Tokens directory has overly permissive permissions",
			logger.String("dir", tokensDir),
			logger.String("permissions", mode.Perm().String()))
	}

	return nil
}
