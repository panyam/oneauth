package fs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/panyam/oneauth/core"
)

// FSConsentStore keeps core.ConsentGrants as one JSON file per user and
// client under <StoragePath>/consents.
//
// Files are named by a hash of subject and client_id, so any characters
// in either are safe and no key can steer the path. Each file holds the
// whole grant, key included, and a read that finds another key's grant
// in the file returns ErrKeyCollision.
//
// A mutex orders writes within one process, and a save replaces the file
// by rename, so a reader sees the old grant or the new one. Two processes
// sharing the directory can interleave a save and a revoke; replicas need
// the GORM or GAE store.
type FSConsentStore struct {
	StoragePath string

	mu sync.Mutex
}

// NewFSConsentStore returns a store rooted at storagePath. The directory
// is created on first write.
func NewFSConsentStore(storagePath string) *FSConsentStore {
	return &FSConsentStore{StoragePath: storagePath}
}

// path names the file by a hash of the key, so two keys never share a
// file. Subject and client_id are both required.
func (s *FSConsentStore) path(subject, clientID string) (string, error) {
	if subject == "" || clientID == "" {
		return "", errors.New("fs: consent subject and client_id are required")
	}
	sum := sha256.Sum256([]byte(subject + "\x00" + clientID))
	return filepath.Join(s.StoragePath, "consents", hex.EncodeToString(sum[:])+".json"), nil
}

// SaveConsent writes req.Grant, replacing any grant for the same subject
// and client_id. The store keeps a copy, so changing req.Grant afterwards
// doesn't change what is stored. Empty subject or client_id is an error.
func (s *FSConsentStore) SaveConsent(_ context.Context, req *core.SaveConsentRequest) (*core.SaveConsentResponse, error) {
	if req == nil || req.Grant == nil {
		return nil, errors.New("SaveConsent: grant is required")
	}
	path, err := s.path(req.Grant.Subject, req.Grant.ClientID)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(req.Grant)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}
	out := *req.Grant
	out.Scopes = slices.Clone(req.Grant.Scopes)
	return &core.SaveConsentResponse{Grant: &out}, nil
}

// GetConsent returns the stored grant, expired or not, decoded fresh from
// the file. It returns core.ErrConsentNotFound when no file exists, and
// ErrKeyCollision when the file holds another key's grant.
func (s *FSConsentStore) GetConsent(_ context.Context, req *core.GetConsentRequest) (*core.GetConsentResponse, error) {
	if req == nil || req.Subject == "" || req.ClientID == "" {
		return nil, core.ErrConsentNotFound
	}
	path, err := s.path(req.Subject, req.ClientID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	data, err := os.ReadFile(path)
	s.mu.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		return nil, core.ErrConsentNotFound
	}
	if err != nil {
		return nil, err
	}
	var g core.ConsentGrant
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("fs: consent file %s: %w", filepath.Base(path), err)
	}
	if g.Subject != req.Subject || g.ClientID != req.ClientID {
		return nil, ErrKeyCollision
	}
	return &core.GetConsentResponse{Grant: &g}, nil
}

// RevokeConsent removes the file. A missing file is not an error, so a
// second revoke succeeds.
func (s *FSConsentStore) RevokeConsent(_ context.Context, req *core.RevokeConsentRequest) (*core.RevokeConsentResponse, error) {
	if req == nil || req.Subject == "" || req.ClientID == "" {
		return &core.RevokeConsentResponse{}, nil
	}
	path, err := s.path(req.Subject, req.ClientID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &core.RevokeConsentResponse{}, nil
}

var _ core.ConsentStore = (*FSConsentStore)(nil)
