package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// fsKeyEntry is the on-disk JSON representation of a signing key.
type fsKeyEntry struct {
	ClientID  string `json:"client_id"`
	Key       []byte `json:"key"`
	Algorithm string `json:"algorithm"`
	Kid       string `json:"kid,omitempty"`
}

// FSKeyStore implements keys.KeyStorage using filesystem storage.
type FSKeyStore struct {
	StoragePath string
	mu          sync.RWMutex
}

// NewFSKeyStore creates a new filesystem-backed KeyStore.
func NewFSKeyStore(storagePath string) *FSKeyStore {
	return &FSKeyStore{StoragePath: storagePath}
}

func (s *FSKeyStore) getKeyDir() string {
	return filepath.Join(s.StoragePath, "signing_keys")
}

func (s *FSKeyStore) getKeyPath(clientID string) (string, error) {
	safeID, err := safeName(clientID)
	if err != nil {
		return "", fmt.Errorf("invalid clientID: %w", err)
	}
	return filepath.Join(s.getKeyDir(), safeID+".json"), nil
}

func (s *FSKeyStore) loadEntry(clientID string) (*fsKeyEntry, error) {
	path, err := s.getKeyPath(clientID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, keys.ErrKeyNotFound
		}
		return nil, err
	}
	var entry fsKeyEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (s *FSKeyStore) PutKey(rec *keys.KeyRecord) error {
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return keys.ErrAlgorithmMismatch
	}

	path, err := s.getKeyPath(rec.ClientID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.getKeyDir(), 0700); err != nil {
		return err
	}

	kid := rec.Kid
	if kid == "" {
		kid, _ = utils.ComputeKid(keyBytes, rec.Algorithm)
	}
	entry := &fsKeyEntry{
		ClientID:  rec.ClientID,
		Key:       keyBytes,
		Algorithm: rec.Algorithm,
		Kid:       kid,
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(path, data)
}

func (s *FSKeyStore) DeleteKey(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.getKeyPath(clientID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return keys.ErrKeyNotFound
	}
	return os.Remove(path)
}

func (s *FSKeyStore) GetKey(clientID string) (*keys.KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.loadEntry(clientID)
	if err != nil {
		return nil, err
	}
	return &keys.KeyRecord{
		ClientID:  entry.ClientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}, nil
}

func (s *FSKeyStore) GetKeyByKid(kid string) (*keys.KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.getKeyDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, keys.ErrKidNotFound
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var entry fsKeyEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		if entry.Kid == kid {
			return &keys.KeyRecord{
				ClientID:  entry.ClientID,
				Key:       entry.Key,
				Algorithm: entry.Algorithm,
				Kid:       entry.Kid,
			}, nil
		}
	}
	return nil, keys.ErrKidNotFound
}

func (s *FSKeyStore) ListKeyIDs() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.getKeyDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var keys []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var entry fsKeyEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		keys = append(keys, entry.ClientID)
	}
	return keys, nil
}

// Backward-compatible aliases

func (s *FSKeyStore) RegisterKey(clientID string, key any, algorithm string) error {
	return s.PutKey(&keys.KeyRecord{ClientID: clientID, Key: key, Algorithm: algorithm})
}

func (s *FSKeyStore) GetVerifyKey(clientID string) (any, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return nil, err
	}
	return rec.Key, nil
}

func (s *FSKeyStore) GetSigningKey(clientID string) (any, error) {
	return s.GetVerifyKey(clientID)
}

func (s *FSKeyStore) GetExpectedAlg(clientID string) (string, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Algorithm, nil
}

func (s *FSKeyStore) ListKeys() ([]string, error) {
	return s.ListKeyIDs()
}

func (s *FSKeyStore) GetCurrentKid(clientID string) (string, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Kid, nil
}
