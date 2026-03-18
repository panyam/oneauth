package fs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/utils"
)

// fsKeyEntry is the on-disk JSON representation of a signing key.
type fsKeyEntry struct {
	ClientID  string `json:"client_id"`
	Key       []byte `json:"key"`
	Algorithm string `json:"algorithm"`
	Kid       string `json:"kid,omitempty"`
}

// FSKeyStore implements oa.KeyStorage using filesystem storage.
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

func (s *FSKeyStore) getKeyPath(clientID string) string {
	safeID := strings.ReplaceAll(clientID, "/", "_")
	return filepath.Join(s.getKeyDir(), safeID+".json")
}

func (s *FSKeyStore) loadEntry(clientID string) (*fsKeyEntry, error) {
	data, err := os.ReadFile(s.getKeyPath(clientID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, oa.ErrKeyNotFound
		}
		return nil, err
	}
	var entry fsKeyEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (s *FSKeyStore) PutKey(rec *oa.KeyRecord) error {
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return oa.ErrAlgorithmMismatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.getKeyDir(), 0755); err != nil {
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
	return writeAtomicFile(s.getKeyPath(rec.ClientID), data)
}

func (s *FSKeyStore) DeleteKey(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.getKeyPath(clientID)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return oa.ErrKeyNotFound
	}
	return os.Remove(path)
}

func (s *FSKeyStore) GetKey(clientID string) (*oa.KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.loadEntry(clientID)
	if err != nil {
		return nil, err
	}
	return &oa.KeyRecord{
		ClientID:  entry.ClientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}, nil
}

func (s *FSKeyStore) GetKeyByKid(kid string) (*oa.KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.getKeyDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, oa.ErrKidNotFound
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
			return &oa.KeyRecord{
				ClientID:  entry.ClientID,
				Key:       entry.Key,
				Algorithm: entry.Algorithm,
				Kid:       entry.Kid,
			}, nil
		}
	}
	return nil, oa.ErrKidNotFound
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
	return s.PutKey(&oa.KeyRecord{ClientID: clientID, Key: key, Algorithm: algorithm})
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
