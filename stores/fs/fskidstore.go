package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/keys"
)

// fsKidEntry is the on-disk JSON representation of a kid→key grace entry.
// Mirrors fsKeyEntry but keyed by kid (not clientID) and carries an expiry
// — the grace-period TTL set when a key is retired during rotation.
type fsKidEntry struct {
	Kid       string    `json:"kid"`
	Key       []byte    `json:"key"`
	Algorithm string    `json:"algorithm"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"` // zero value = no expiry
}

// FSKidStore implements keys.KidStorage using filesystem storage.
// One file per kid under {StoragePath}/kid_keys/, mirroring FSKeyStore's
// file-per-record layout.
type FSKidStore struct {
	StoragePath string
	mu          sync.RWMutex
}

var _ keys.KidStorage = (*FSKidStore)(nil)

// NewFSKidStore creates a new filesystem-backed KidStorage.
func NewFSKidStore(storagePath string) *FSKidStore {
	return &FSKidStore{StoragePath: storagePath}
}

func (s *FSKidStore) getKidDir() string {
	return filepath.Join(s.StoragePath, "kid_keys")
}

func (s *FSKidStore) getKidPath(kid string) (string, error) {
	safeKid, err := safeName(kid)
	if err != nil {
		return "", fmt.Errorf("invalid kid: %w", err)
	}
	return filepath.Join(s.getKidDir(), safeKid+".json"), nil
}

// isExpired matches keys.kidRecord.isExpired: zero time = never expires.
func isExpired(t time.Time) bool {
	return !t.IsZero() && time.Now().After(t)
}

func (s *FSKidStore) Add(kid string, key any, algorithm string, clientID string, expiresAt time.Time) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return keys.ErrAlgorithmMismatch
	}

	path, err := s.getKidPath(kid)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.getKidDir(), 0700); err != nil {
		return err
	}

	entry := &fsKidEntry{
		Kid:       kid,
		Key:       keyBytes,
		Algorithm: algorithm,
		ClientID:  clientID,
		ExpiresAt: expiresAt,
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(path, data)
}

// Remove is idempotent — deleting an absent kid is not an error.
func (s *FSKidStore) Remove(kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.getKidPath(kid)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// GetKey always returns ErrKeyNotFound — KidStorage is kid-indexed and
// has no clientID→key lookup. Matches the in-memory KidStore.
func (s *FSKidStore) GetKey(clientID string) (*keys.KeyRecord, error) {
	return nil, keys.ErrKeyNotFound
}

func (s *FSKidStore) GetKeyByKid(kid string) (*keys.KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path, err := s.getKidPath(kid)
	if err != nil {
		return nil, keys.ErrKidNotFound
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, keys.ErrKidNotFound
		}
		return nil, err
	}
	var entry fsKidEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	if isExpired(entry.ExpiresAt) {
		return nil, keys.ErrKidNotFound
	}
	return &keys.KeyRecord{
		ClientID:  entry.ClientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}, nil
}

func (s *FSKidStore) CleanExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.getKidDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var entry fsKidEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		if isExpired(entry.ExpiresAt) {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
