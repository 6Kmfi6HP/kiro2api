package dashboard

import (
	"fmt"
	"sync"
	"time"
)

// OAuthState holds OAuth state data with expiration
type OAuthState struct {
	State         string
	CodeVerifier  string
	CodeChallenge string
	Provider      string
	Region        string
	StartURL      string
	RedirectURI   string // Store redirect URI for token exchange
	ClientID      string // For IdC authentication
	ClientSecret  string // For IdC authentication
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// StateStore manages OAuth state with TTL
type StateStore struct {
	states sync.Map
	mu     sync.Mutex
	stopCh chan struct{}
}

// NewStateStore creates a new state store with background cleanup
func NewStateStore() *StateStore {
	store := &StateStore{
		stopCh: make(chan struct{}),
	}

	// Start background cleanup goroutine
	go store.cleanupLoop()

	return store
}

// SaveState stores OAuth state with 5-minute TTL
func (s *StateStore) SaveState(state string, data *OAuthState) error {
	if state == "" {
		return fmt.Errorf("state cannot be empty")
	}
	if data == nil {
		return fmt.Errorf("data cannot be nil")
	}

	// Set timestamps
	now := time.Now()
	data.CreatedAt = now
	data.ExpiresAt = now.Add(5 * time.Minute) // 5-minute TTL

	s.states.Store(state, data)
	return nil
}

// GetState retrieves and validates OAuth state
func (s *StateStore) GetState(state string) (*OAuthState, error) {
	if state == "" {
		return nil, fmt.Errorf("state cannot be empty")
	}

	value, ok := s.states.Load(state)
	if !ok {
		return nil, fmt.Errorf("state not found")
	}

	data, ok := value.(*OAuthState)
	if !ok {
		return nil, fmt.Errorf("invalid state data type")
	}

	// Check expiration
	if time.Now().After(data.ExpiresAt) {
		s.states.Delete(state)
		return nil, fmt.Errorf("state expired")
	}

	return data, nil
}

// DeleteState removes OAuth state after use
func (s *StateStore) DeleteState(state string) {
	if state != "" {
		s.states.Delete(state)
	}
}

// CleanupExpired removes all expired states
func (s *StateStore) CleanupExpired() int {
	count := 0
	now := time.Now()

	s.states.Range(func(key, value interface{}) bool {
		data, ok := value.(*OAuthState)
		if !ok {
			// Invalid data type, delete it
			s.states.Delete(key)
			count++
			return true
		}

		if now.After(data.ExpiresAt) {
			s.states.Delete(key)
			count++
		}

		return true
	})

	return count
}

// cleanupLoop runs background cleanup every minute
func (s *StateStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.CleanupExpired()
		case <-s.stopCh:
			return
		}
	}
}

// Stop stops the background cleanup goroutine
func (s *StateStore) Stop() {
	close(s.stopCh)
}

// Count returns the number of states in the store
func (s *StateStore) Count() int {
	count := 0
	s.states.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
