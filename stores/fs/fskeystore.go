package fs

import (
	"context"
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

func (s *FSKeyStore) PutKey(ctx context.Context, req *keys.PutKeyRequest) (*keys.PutKeyResponse, error) {
	if req == nil || req.Record == nil {
		return nil, fmt.Errorf("PutKey: req.Record is required")
	}
	rec := req.Record
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return nil, keys.ErrAlgorithmMismatch
	}

	path, err := s.getKeyPath(rec.ClientID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.getKeyDir(), 0700); err != nil {
		return nil, err
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
		return nil, err
	}
	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}
	return &keys.PutKeyResponse{}, nil
}

func (s *FSKeyStore) DeleteKey(ctx context.Context, req *keys.DeleteKeyRequest) (*keys.DeleteKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteKey: req is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.getKeyPath(req.ClientID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, keys.ErrKeyNotFound
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return &keys.DeleteKeyResponse{}, nil
}

func (s *FSKeyStore) GetKey(ctx context.Context, req *keys.GetKeyRequest) (*keys.GetKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKey: req is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.loadEntry(req.ClientID)
	if err != nil {
		return nil, err
	}
	return &keys.GetKeyResponse{Record: &keys.KeyRecord{
		ClientID:  entry.ClientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}}, nil
}

func (s *FSKeyStore) GetKeyByKid(ctx context.Context, req *keys.GetKeyByKidRequest) (*keys.GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
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
		if entry.Kid == req.Kid {
			return &keys.GetKeyByKidResponse{Record: &keys.KeyRecord{
				ClientID:  entry.ClientID,
				Key:       entry.Key,
				Algorithm: entry.Algorithm,
				Kid:       entry.Kid,
			}}, nil
		}
	}
	return nil, keys.ErrKidNotFound
}

func (s *FSKeyStore) ListKeyIDs(ctx context.Context, req *keys.ListKeyIDsRequest) (*keys.ListKeyIDsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.getKeyDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &keys.ListKeyIDsResponse{ClientIDs: []string{}}, nil
		}
		return nil, err
	}

	var ids []string
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
		ids = append(ids, entry.ClientID)
	}
	return &keys.ListKeyIDsResponse{ClientIDs: ids}, nil
}
