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

	"github.com/panyam/oneauth/keys"
)

// fsKidEntry is the on-disk JSON representation of a kid→key grace entry.
type fsKidEntry struct {
	Kid       string    `json:"kid"`
	Key       []byte    `json:"key"`
	Algorithm string    `json:"algorithm"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"` // zero value = no expiry
}

// FSKidStore implements keys.KidStorage using filesystem storage.
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

func isExpired(t time.Time) bool {
	return !t.IsZero() && time.Now().After(t)
}

func (s *FSKidStore) Add(ctx context.Context, req *keys.AddKidRequest) (*keys.AddKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Add: req is required")
	}
	keyBytes, ok := req.Key.([]byte)
	if !ok {
		return nil, keys.ErrAlgorithmMismatch
	}

	path, err := s.getKidPath(req.Kid)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.getKidDir(), 0700); err != nil {
		return nil, err
	}

	entry := &fsKidEntry{
		Kid:       req.Kid,
		Key:       keyBytes,
		Algorithm: req.Algorithm,
		ClientID:  req.ClientID,
		ExpiresAt: req.ExpiresAt,
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}
	return &keys.AddKidResponse{}, nil
}

func (s *FSKidStore) Remove(ctx context.Context, req *keys.RemoveKidRequest) (*keys.RemoveKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Remove: req is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.getKidPath(req.Kid)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return &keys.RemoveKidResponse{}, nil
}

func (s *FSKidStore) GetKey(ctx context.Context, req *keys.GetKeyRequest) (*keys.GetKeyResponse, error) {
	return nil, keys.ErrKeyNotFound
}

func (s *FSKidStore) GetKeyByKid(ctx context.Context, req *keys.GetKeyByKidRequest) (*keys.GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	path, err := s.getKidPath(req.Kid)
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
	return &keys.GetKeyByKidResponse{Record: &keys.KeyRecord{
		ClientID:  entry.ClientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}}, nil
}

func (s *FSKidStore) CleanExpired(ctx context.Context, req *keys.CleanExpiredRequest) (*keys.CleanExpiredResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.getKidDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &keys.CleanExpiredResponse{}, nil
		}
		return nil, err
	}

	removed := 0
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
				return nil, err
			}
			removed++
		}
	}
	return &keys.CleanExpiredResponse{Removed: removed}, nil
}
