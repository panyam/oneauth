package fs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
)

// FSAuthorizationCodeStore keeps RFC 6749 §4.1 authorization codes as one
// JSON file each under <StoragePath>/authorization_codes/.
//
// Files are named by core.AtRestKey(code), and the JSON leaves the code
// out, so a copy of the directory can't redeem a code. Lookups hash the
// presented code to find its file.
//
// A mutex covers every read-modify-write, so ConsumeAuthorizationCode and
// RecordAuthorizationCodeTokens are atomic against each other within one
// process, as the AuthorizationCodeStore contract needs for reuse
// detection. Two processes sharing the directory are not covered;
// replicas need the GORM or GAE store.
type FSAuthorizationCodeStore struct {
	StoragePath string

	mu sync.Mutex
}

// NewFSAuthorizationCodeStore returns a store rooted at storagePath. The
// directory is created on first write.
func NewFSAuthorizationCodeStore(storagePath string) *FSAuthorizationCodeStore {
	return &FSAuthorizationCodeStore{StoragePath: storagePath}
}

func (s *FSAuthorizationCodeStore) dir() string {
	return filepath.Join(s.StoragePath, "authorization_codes")
}

// atRestFileName is the file name for a single-use value: the hex digest
// from core.AtRestKey, which never contains a path separator.
func atRestFileName(value string) string {
	return strings.TrimPrefix(core.AtRestKey(value), "sha256:") + ".json"
}

func (s *FSAuthorizationCodeStore) path(code string) string {
	return filepath.Join(s.dir(), atRestFileName(code))
}

// read loads code's record, with Code filled back in from the argument.
// A missing file is core.ErrAuthorizationCodeNotFound.
func (s *FSAuthorizationCodeStore) read(code string) (*core.AuthorizationCode, error) {
	data, err := os.ReadFile(s.path(code))
	if errors.Is(err, os.ErrNotExist) {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec core.AuthorizationCode
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("fs: authorization code file: %w", err)
	}
	rec.Code = code
	return &rec, nil
}

// write stores rec without its code, atomically by rename.
func (s *FSAuthorizationCodeStore) write(rec *core.AuthorizationCode) error {
	out := *rec
	out.Code = ""
	data, err := json.Marshal(&out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir(), 0o700); err != nil {
		return err
	}
	return writeAtomicFile(s.path(rec.Code), data)
}

// CreateAuthorizationCode stores a new code. A code that already has a
// file is a generic error, matching the in-memory store: the caller drew
// it from a CSPRNG, so a collision is a bug rather than a condition.
func (s *FSAuthorizationCodeStore) CreateAuthorizationCode(_ context.Context, req *core.CreateAuthorizationCodeRequest) (*core.CreateAuthorizationCodeResponse, error) {
	if req == nil || req.Code == nil || req.Code.Code == "" {
		return nil, errors.New("CreateAuthorizationCode: code is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(s.path(req.Code.Code)); err == nil {
		return nil, errors.New("CreateAuthorizationCode: code collision")
	}
	if err := s.write(req.Code); err != nil {
		return nil, err
	}
	return &core.CreateAuthorizationCodeResponse{}, nil
}

// GetAuthorizationCode returns the record or
// core.ErrAuthorizationCodeNotFound. It doesn't filter by expiry, so the
// token endpoint can tell an expired code from an unknown one.
func (s *FSAuthorizationCodeStore) GetAuthorizationCode(_ context.Context, req *core.GetAuthorizationCodeRequest) (*core.GetAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.read(req.Code)
	if err != nil {
		return nil, err
	}
	return &core.GetAuthorizationCodeResponse{Code: rec}, nil
}

// ConsumeAuthorizationCode marks an unused code used and returns the
// record as it was. For a used code it sets ReuseDetected and returns
// core.ErrAuthorizationCodeUsed with the record, whose Issued* fields
// name the tokens to revoke. A missing code is
// core.ErrAuthorizationCodeNotFound.
func (s *FSAuthorizationCodeStore) ConsumeAuthorizationCode(_ context.Context, req *core.ConsumeAuthorizationCodeRequest) (*core.ConsumeAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.read(req.Code)
	if err != nil {
		return nil, err
	}
	before := *rec
	if rec.IsUsed() {
		rec.ReuseDetected = true
		if err := s.write(rec); err != nil {
			return nil, err
		}
		return &core.ConsumeAuthorizationCodeResponse{Code: &before}, core.ErrAuthorizationCodeUsed
	}
	rec.UsedAt = time.Now()
	if err := s.write(rec); err != nil {
		return nil, err
	}
	return &core.ConsumeAuthorizationCodeResponse{Code: &before}, nil
}

// RecordAuthorizationCodeTokens stores the tokens a redemption minted and
// reports ReuseDetected, read under the same lock as the write. A missing
// code is core.ErrAuthorizationCodeNotFound.
func (s *FSAuthorizationCodeStore) RecordAuthorizationCodeTokens(_ context.Context, req *core.RecordAuthorizationCodeTokensRequest) (*core.RecordAuthorizationCodeTokensResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.read(req.Code)
	if err != nil {
		return nil, err
	}
	rec.IssuedTokenID = req.TokenID
	rec.IssuedTokenExpiresAt = req.TokenExpiresAt
	rec.IssuedRefreshFamily = req.RefreshFamily
	if err := s.write(rec); err != nil {
		return nil, err
	}
	return &core.RecordAuthorizationCodeTokensResponse{ReuseDetected: rec.ReuseDetected}, nil
}

// DeleteAuthorizationCode removes the code's file, or returns
// core.ErrAuthorizationCodeNotFound when there is none, so a caller can
// tell a second delete from a first.
func (s *FSAuthorizationCodeStore) DeleteAuthorizationCode(_ context.Context, req *core.DeleteAuthorizationCodeRequest) (*core.DeleteAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(req.Code))
	if errors.Is(err, os.ErrNotExist) {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	if err != nil {
		return nil, err
	}
	return &core.DeleteAuthorizationCodeResponse{}, nil
}

// CleanupExpired removes every record past its RetainUntil: the code's
// expiry, or for a used code with a recorded token, that token's later
// expiry. It reads every file, which is fine at FS-store scale. A file
// that won't parse is left alone and doesn't stop the sweep.
func (s *FSAuthorizationCodeStore) CleanupExpired(_ context.Context, _ *core.CleanupExpiredAuthorizationCodesRequest) (*core.CleanupExpiredAuthorizationCodesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir())
	if errors.Is(err, os.ErrNotExist) {
		return &core.CleanupExpiredAuthorizationCodesResponse{}, nil
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(s.dir(), e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var rec core.AuthorizationCode
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		if !now.Before(rec.RetainUntil()) {
			if os.Remove(p) == nil {
				removed++
			}
		}
	}
	return &core.CleanupExpiredAuthorizationCodesResponse{Removed: removed}, nil
}

var _ core.AuthorizationCodeStore = (*FSAuthorizationCodeStore)(nil)
