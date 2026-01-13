package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	oa "github.com/panyam/oneauth"
)

// FSAPIKeyStore stores API keys as JSON files
type FSAPIKeyStore struct {
	StoragePath string
	mu          sync.RWMutex
}

// NewFSAPIKeyStore creates a new file-based API key store
func NewFSAPIKeyStore(storagePath string) *FSAPIKeyStore {
	return &FSAPIKeyStore{StoragePath: storagePath}
}

// getKeyDir returns the directory for API keys
func (s *FSAPIKeyStore) getKeyDir() string {
	return filepath.Join(s.StoragePath, "api_keys")
}

// getKeyPath returns the file path for an API key by its ID
func (s *FSAPIKeyStore) getKeyPath(keyID string) string {
	// Sanitize keyID for filename
	safeID := strings.ReplaceAll(keyID, "/", "_")
	return filepath.Join(s.getKeyDir(), safeID+".json")
}

// CreateAPIKey creates a new API key and returns the full key (only shown once)
// The key format is: keyID + "_" + secret
func (s *FSAPIKeyStore) CreateAPIKey(userID, name string, scopes []string, expiresAt *time.Time) (fullKey string, apiKey *oa.APIKey, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate key ID and secret
	keyID, err := oa.GenerateAPIKeyID()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	secret, err := oa.GenerateAPIKeySecret()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate key secret: %w", err)
	}

	// Hash the secret with bcrypt
	keyHash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, fmt.Errorf("failed to hash key: %w", err)
	}

	now := time.Now()
	apiKey = &oa.APIKey{
		KeyID:      keyID,
		KeyHash:    string(keyHash),
		UserID:     userID,
		Name:       name,
		Scopes:     scopes,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.saveKey(apiKey); err != nil {
		return "", nil, err
	}

	// Return the full key (keyID_secret) - this is the only time the secret is available
	fullKey = keyID + "_" + secret
	return fullKey, apiKey, nil
}

// saveKey saves an API key to disk
func (s *FSAPIKeyStore) saveKey(key *oa.APIKey) error {
	path := s.getKeyPath(key.KeyID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}

// GetAPIKeyByID retrieves an API key by its public ID
func (s *FSAPIKeyStore) GetAPIKeyByID(keyID string) (*oa.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getKeyUnsafe(keyID)
}

// getKeyUnsafe retrieves a key without locking (caller must hold lock)
func (s *FSAPIKeyStore) getKeyUnsafe(keyID string) (*oa.APIKey, error) {
	path := s.getKeyPath(keyID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, oa.ErrAPIKeyNotFound
		}
		return nil, err
	}

	var apiKey oa.APIKey
	if err := json.Unmarshal(data, &apiKey); err != nil {
		return nil, err
	}

	return &apiKey, nil
}

// ValidateAPIKey validates a full API key and returns the key metadata if valid
// The fullKey format is: keyID + "_" + secret
func (s *FSAPIKeyStore) ValidateAPIKey(fullKey string) (*oa.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Parse the full key
	parts := strings.SplitN(fullKey, "_", 3) // oa_keyid_secret -> ["oa", "keyid", "secret"]
	if len(parts) != 3 || parts[0] != "oa" {
		return nil, oa.ErrAPIKeyNotFound
	}

	keyID := parts[0] + "_" + parts[1] // Reconstruct keyID: "oa_keyid"
	secret := parts[2]

	// Get the key
	apiKey, err := s.getKeyUnsafe(keyID)
	if err != nil {
		return nil, err
	}

	// Check if revoked
	if apiKey.Revoked {
		return nil, oa.ErrTokenRevoked
	}

	// Check if expired
	if apiKey.IsExpired() {
		return nil, oa.ErrTokenExpired
	}

	// Verify the secret
	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(secret)); err != nil {
		return nil, oa.ErrAPIKeyNotFound
	}

	return apiKey, nil
}

// RevokeAPIKey marks an API key as revoked
func (s *FSAPIKeyStore) RevokeAPIKey(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	apiKey, err := s.getKeyUnsafe(keyID)
	if err != nil {
		return err
	}

	if apiKey.Revoked {
		return nil // Already revoked
	}

	now := time.Now()
	apiKey.Revoked = true
	apiKey.RevokedAt = &now
	return s.saveKey(apiKey)
}

// ListUserAPIKeys returns all API keys for a user (without secrets)
func (s *FSAPIKeyStore) ListUserAPIKeys(userID string) ([]*oa.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []*oa.APIKey
	keysDir := s.getKeyDir()

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(keysDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var apiKey oa.APIKey
		if err := json.Unmarshal(data, &apiKey); err != nil {
			continue
		}

		if apiKey.UserID == userID {
			// Clear the hash for security (not needed in listings)
			apiKey.KeyHash = ""
			keys = append(keys, &apiKey)
		}
	}

	return keys, nil
}

// UpdateAPIKeyLastUsed updates the last used timestamp
func (s *FSAPIKeyStore) UpdateAPIKeyLastUsed(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	apiKey, err := s.getKeyUnsafe(keyID)
	if err != nil {
		return err
	}

	apiKey.LastUsedAt = time.Now()
	return s.saveKey(apiKey)
}
