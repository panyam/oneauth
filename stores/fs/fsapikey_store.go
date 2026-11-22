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
	if err := checkOwner(path, key.KeyID, apiKeyID); err != nil {
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
	apiKey, err := readKeyed(path, keyID, apiKeyID)
	if err != nil {
		return nil, err
	}
	if apiKey == nil {
		return nil, core.ErrAPIKeyNotFound
	}
	return apiKey, nil
}

func apiKeyID(k *core.APIKey) string { return k.KeyID }

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

// ListAPIKeys returns every key under api_keys/, with KeyHash cleared. A
// file deleted between the directory read and the file read is another
// handle's cleanup at work, so the key is left out rather than failing the
// listing (agni issue 1796). Any other read or decode error fails it.
// Order is unspecified.
func (s *FSAPIKeyStore) ListAPIKeys(ctx context.Context, req *core.ListAPIKeysRequest) (*core.ListAPIKeysResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys, err := s.readAllKeys()
	if err != nil {
		return nil, err
	}
	out := make([]*core.APIKey, len(keys))
	for i, k := range keys {
		k.key.KeyHash = ""
		out[i] = k.key
	}
	return &core.ListAPIKeysResponse{APIKeys: out}, nil
}

// CleanupExpiredAPIKeys deletes every key whose ExpiresAt is at or before
// req.CleanupTime(), revoked or not, and keeps keys with no expiry. A file
// that's already gone when the delete runs was removed by another handle,
// so it isn't counted and isn't an error. Removed counts the files this
// call deleted.
func (s *FSAPIKeyStore) CleanupExpiredAPIKeys(ctx context.Context, req *core.CleanupExpiredAPIKeysRequest) (*core.CleanupExpiredAPIKeysResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := req.CleanupTime()
	keys, err := s.readAllKeys()
	if err != nil {
		return nil, err
	}
	removed := 0
	for _, k := range keys {
		if k.key.ExpiresAt == nil || k.key.ExpiresAt.After(now) {
			continue
		}
		if err := os.Remove(k.path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return &core.CleanupExpiredAPIKeysResponse{Removed: removed}, err
		}
		removed++
	}
	return &core.CleanupExpiredAPIKeysResponse{Removed: removed}, nil
}

type storedAPIKey struct {
	path string
	key  *core.APIKey
}

// readAllKeys decodes every .json file in the key directory, skipping files
// that vanish mid-scan. The caller holds s.mu.
func (s *FSAPIKeyStore) readAllKeys() ([]storedAPIKey, error) {
	dir := s.getKeyDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var keys []storedAPIKey
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var k core.APIKey
		if err := json.Unmarshal(data, &k); err != nil {
			return nil, fmt.Errorf("api key file %s: %w", entry.Name(), err)
		}
		keys = append(keys, storedAPIKey{path: path, key: &k})
	}
	return keys, nil
}
