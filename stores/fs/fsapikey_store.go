package fs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/panyam/oneauth/core"
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

func (s *FSAPIKeyStore) getKeyDir() string {
	return filepath.Join(s.StoragePath, "api_keys")
}

func (s *FSAPIKeyStore) getKeyPath(keyID string) (string, error) {
	safeID, err := safeName(keyID)
	if err != nil {
		return "", fmt.Errorf("invalid keyID: %w", err)
	}
	return filepath.Join(s.getKeyDir(), safeID+".json"), nil
}

func (s *FSAPIKeyStore) CreateAPIKey(ctx context.Context, req *core.CreateAPIKeyRequest) (*core.CreateAPIKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyID, err := core.GenerateAPIKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	secret, err := core.GenerateAPIKeySecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key secret: %w", err)
	}

	keyHash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash key: %w", err)
	}

	now := time.Now()
	apiKey := &core.APIKey{
		KeyID:      keyID,
		KeyHash:    string(keyHash),
		Subject:    req.Subject,
		Name:       req.Name,
		Scopes:     req.Scopes,
		CreatedAt:  now,
		ExpiresAt:  req.ExpiresAt,
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.saveKey(apiKey); err != nil {
		return nil, err
	}

	fullKey := keyID + "_" + secret
	return &core.CreateAPIKeyResponse{FullKey: fullKey, APIKey: apiKey}, nil
}

func (s *FSAPIKeyStore) saveKey(key *core.APIKey) error {
	path, err := s.getKeyPath(key.KeyID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}

func (s *FSAPIKeyStore) GetAPIKeyByID(ctx context.Context, req *core.GetAPIKeyByIDRequest) (*core.GetAPIKeyByIDResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, err := s.getKeyUnsafe(req.KeyID)
	if err != nil {
		return nil, err
	}
	return &core.GetAPIKeyByIDResponse{APIKey: key}, nil
}

func (s *FSAPIKeyStore) getKeyUnsafe(keyID string) (*core.APIKey, error) {
	path, err := s.getKeyPath(keyID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.ErrAPIKeyNotFound
		}
		return nil, err
	}

	var apiKey core.APIKey
	if err := json.Unmarshal(data, &apiKey); err != nil {
		return nil, err
	}

	return &apiKey, nil
}

func (s *FSAPIKeyStore) ValidateAPIKey(ctx context.Context, req *core.ValidateAPIKeyRequest) (*core.ValidateAPIKeyResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parts := strings.SplitN(req.FullKey, "_", 3)
	if len(parts) != 3 || parts[0] != "oa" {
		return nil, core.ErrAPIKeyNotFound
	}

	keyID := parts[0] + "_" + parts[1]
	secret := parts[2]

	apiKey, err := s.getKeyUnsafe(keyID)
	if err != nil {
		return nil, err
	}

	if apiKey.Revoked {
		return nil, core.ErrTokenRevoked
	}

	if apiKey.IsExpired() {
		return nil, core.ErrTokenExpired
	}

	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(secret)); err != nil {
		return nil, core.ErrAPIKeyNotFound
	}

	return &core.ValidateAPIKeyResponse{APIKey: apiKey}, nil
}

func (s *FSAPIKeyStore) RevokeAPIKey(ctx context.Context, req *core.RevokeAPIKeyRequest) (*core.RevokeAPIKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	apiKey, err := s.getKeyUnsafe(req.KeyID)
	if err != nil {
		return nil, err
	}

	if apiKey.Revoked {
		return &core.RevokeAPIKeyResponse{}, nil
	}

	now := time.Now()
	apiKey.Revoked = true
	apiKey.RevokedAt = &now
	if err := s.saveKey(apiKey); err != nil {
		return nil, err
	}
	return &core.RevokeAPIKeyResponse{}, nil
}

func (s *FSAPIKeyStore) ListSubjectAPIKeys(ctx context.Context, req *core.ListSubjectAPIKeysRequest) (*core.ListSubjectAPIKeysResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []*core.APIKey
	keysDir := s.getKeyDir()

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &core.ListSubjectAPIKeysResponse{APIKeys: keys}, nil
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

		var apiKey core.APIKey
		if err := json.Unmarshal(data, &apiKey); err != nil {
			continue
		}

		if apiKey.Subject == req.Subject {
			apiKey.KeyHash = ""
			keys = append(keys, &apiKey)
		}
	}

	return &core.ListSubjectAPIKeysResponse{APIKeys: keys}, nil
}

func (s *FSAPIKeyStore) UpdateAPIKeyLastUsed(ctx context.Context, req *core.UpdateAPIKeyLastUsedRequest) (*core.UpdateAPIKeyLastUsedResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	apiKey, err := s.getKeyUnsafe(req.KeyID)
	if err != nil {
		return nil, err
	}

	apiKey.LastUsedAt = time.Now()
	if err := s.saveKey(apiKey); err != nil {
		return nil, err
	}
	return &core.UpdateAPIKeyLastUsedResponse{}, nil
}
