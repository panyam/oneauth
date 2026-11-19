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
	"sync"
	"time"

	"github.com/panyam/oneauth/outbound"
)

// FSUserTokenStore keeps outbound.UserTokenRecords as one JSON file each
// under <StoragePath>/user_tokens. The sealed bytes are written as given,
// so the files hold ciphertext only.
//
// The compare-and-swap in PutUserToken holds within one process: a mutex
// covers the read, the version check and the atomic rename. Two processes
// sharing the directory can both pass the check, so replicas that refresh
// tokens need a GORM or GAE store.
type FSUserTokenStore struct {
	StoragePath string

	mu sync.Mutex
}

// NewFSUserTokenStore returns a store rooted at storagePath. The directory
// is created on first write.
func NewFSUserTokenStore(storagePath string) *FSUserTokenStore {
	return &FSUserTokenStore{StoragePath: storagePath}
}

type fsUserToken struct {
	Provider  string    `json:"provider"`
	Subject   string    `json:"subject"`
	Sealed    []byte    `json:"sealed"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// path names the file by a hash of the key rather than the key itself, so
// two keys never share a file and no key can steer the path.
func (s *FSUserTokenStore) path(provider, subject string) (string, error) {
	if provider == "" || subject == "" {
		return "", fmt.Errorf("fs: user token provider and subject are required")
	}
	sum := sha256.Sum256([]byte(provider + "\x00" + subject))
	return filepath.Join(s.StoragePath, "user_tokens", hex.EncodeToString(sum[:])+".json"), nil
}

// read returns the record at the key, or outbound.ErrUserTokenNotFound.
func (s *FSUserTokenStore) read(provider, subject string) (*fsUserToken, string, error) {
	path, err := s.path(provider, subject)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, path, outbound.ErrUserTokenNotFound
	}
	if err != nil {
		return nil, path, err
	}
	var rec fsUserToken
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, path, fmt.Errorf("fs: user token file %s: %w", filepath.Base(path), err)
	}
	if rec.Provider != provider || rec.Subject != subject {
		return nil, path, ErrKeyCollision
	}
	return &rec, path, nil
}

// GetUserToken returns the record, outbound.ErrUserTokenNotFound when no
// file exists, or ErrKeyCollision when the file names another key.
func (s *FSUserTokenStore) GetUserToken(_ context.Context, req *outbound.GetUserTokenRequest) (*outbound.GetUserTokenResponse, error) {
	rec, _, err := s.read(req.Provider, req.Subject)
	if err != nil {
		return nil, err
	}
	return &outbound.GetUserTokenResponse{Record: &outbound.UserTokenRecord{
		Provider: rec.Provider, Subject: rec.Subject, Sealed: rec.Sealed, Version: rec.Version, UpdatedAt: rec.UpdatedAt,
	}}, nil
}

// PutUserToken writes if the stored version equals ExpectedVersion (zero
// meaning no file exists) and answers outbound.ErrVersionConflict
// otherwise. The file is replaced by rename, so a reader sees the old or
// the new record, never a mix.
func (s *FSUserTokenStore) PutUserToken(_ context.Context, req *outbound.PutUserTokenRequest) (*outbound.PutUserTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, path, err := s.read(req.Provider, req.Subject)
	var have int64
	switch {
	case err == nil:
		have = cur.Version
	case !errors.Is(err, outbound.ErrUserTokenNotFound):
		return nil, err
	}
	if have != req.ExpectedVersion {
		return nil, outbound.ErrVersionConflict
	}
	rec := fsUserToken{Provider: req.Provider, Subject: req.Subject, Sealed: req.Sealed, Version: have + 1, UpdatedAt: time.Now()}
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}
	return &outbound.PutUserTokenResponse{Version: rec.Version}, nil
}

// DeleteUserToken removes the file. A missing file is not an error.
func (s *FSUserTokenStore) DeleteUserToken(_ context.Context, req *outbound.DeleteUserTokenRequest) (*outbound.DeleteUserTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := s.path(req.Provider, req.Subject)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &outbound.DeleteUserTokenResponse{}, nil
}

var _ outbound.UserTokenStore = (*FSUserTokenStore)(nil)
