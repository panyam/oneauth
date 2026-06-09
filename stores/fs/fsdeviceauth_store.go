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
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
)

// FSDeviceAuthorizationStore persists RFC 8628 device authorizations as
// per-record JSON files under <storage>/device_authorizations/. Two
// files are written per record so user_code lookup is also O(1):
//
//	<storage>/device_authorizations/dc-<sha256(device_code)>.json
//	<storage>/device_authorizations/uc-<sha256(upper(user_code))>.json
//
// The user_code file contains the device_code hash so GetByUserCode can
// resolve via a single extra read. Both files are written and removed
// atomically; the device_code file is the source of truth for the record
// payload.
type FSDeviceAuthorizationStore struct {
	StoragePath string
	mu          sync.RWMutex
}

// NewFSDeviceAuthorizationStore returns a store rooted at storagePath.
func NewFSDeviceAuthorizationStore(storagePath string) *FSDeviceAuthorizationStore {
	return &FSDeviceAuthorizationStore{StoragePath: storagePath}
}

func (s *FSDeviceAuthorizationStore) dir() string {
	return filepath.Join(s.StoragePath, "device_authorizations")
}

func (s *FSDeviceAuthorizationStore) deviceCodePath(deviceCode string) string {
	h := sha256.Sum256([]byte(deviceCode))
	return filepath.Join(s.dir(), "dc-"+hex.EncodeToString(h[:])+".json")
}

func (s *FSDeviceAuthorizationStore) userCodePath(userCode string) string {
	upper := upperUserCode(userCode)
	h := sha256.Sum256([]byte(upper))
	return filepath.Join(s.dir(), "uc-"+hex.EncodeToString(h[:])+".json")
}

func (s *FSDeviceAuthorizationStore) CreateDeviceAuthorization(_ context.Context, req *core.CreateDeviceAuthorizationRequest) (*core.CreateDeviceAuthorizationResponse, error) {
	if req == nil || req.Authorization == nil {
		return nil, errors.New("CreateDeviceAuthorization: authorization is required")
	}
	a := req.Authorization
	if a.DeviceCode == "" || a.UserCode == "" {
		return nil, errors.New("CreateDeviceAuthorization: device_code and user_code are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(s.deviceCodePath(a.DeviceCode)); err == nil {
		return nil, errors.New("CreateDeviceAuthorization: device_code collision")
	}
	if _, err := os.Stat(s.userCodePath(a.UserCode)); err == nil {
		return nil, errors.New("CreateDeviceAuthorization: user_code collision")
	}
	if err := os.MkdirAll(s.dir(), 0o755); err != nil {
		return nil, fmt.Errorf("CreateDeviceAuthorization: mkdir: %w", err)
	}
	if err := writeJSON(s.deviceCodePath(a.DeviceCode), a); err != nil {
		return nil, err
	}
	// The user_code file is a tiny pointer record holding the device_code
	// for the reverse lookup.
	if err := writeJSON(s.userCodePath(a.UserCode), userCodePointer{DeviceCode: a.DeviceCode}); err != nil {
		// Best-effort rollback: remove the dc file so we don't leave a
		// half-created record. Errors from rollback are intentionally
		// swallowed — the caller's error tells them creation failed.
		_ = os.Remove(s.deviceCodePath(a.DeviceCode))
		return nil, err
	}
	return &core.CreateDeviceAuthorizationResponse{}, nil
}

// userCodePointer is the wire shape of the small file written at
// uc-<hash>.json so GetByUserCode can resolve to a device_code in O(1).
type userCodePointer struct {
	DeviceCode string `json:"device_code"`
}

func (s *FSDeviceAuthorizationStore) GetByDeviceCode(_ context.Context, req *core.GetByDeviceCodeRequest) (*core.GetByDeviceCodeResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, err := s.readDeviceCode(req.DeviceCode)
	if err != nil {
		return nil, err
	}
	return &core.GetByDeviceCodeResponse{Authorization: a}, nil
}

func (s *FSDeviceAuthorizationStore) GetByUserCode(_ context.Context, req *core.GetByUserCodeRequest) (*core.GetByUserCodeResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	dc, err := s.resolveUserCode(req.UserCode)
	if err != nil {
		return nil, err
	}
	a, err := s.readDeviceCode(dc)
	if err != nil {
		return nil, err
	}
	return &core.GetByUserCodeResponse{Authorization: a}, nil
}

func (s *FSDeviceAuthorizationStore) ApproveDeviceAuthorization(_ context.Context, req *core.ApproveDeviceAuthorizationRequest) (*core.ApproveDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, err := s.resolveUserCode(req.UserCode)
	if err != nil {
		return nil, err
	}
	a, err := s.readDeviceCode(dc)
	if err != nil {
		return nil, err
	}
	if a.Status != core.DeviceAuthorizationStatusPending {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	a.Status = core.DeviceAuthorizationStatusApproved
	a.ApprovedSubject = req.ApprovedSubject
	if req.GrantedScopes != nil {
		a.Scopes = req.GrantedScopes
	}
	if err := writeJSON(s.deviceCodePath(a.DeviceCode), a); err != nil {
		return nil, err
	}
	clone := *a
	return &core.ApproveDeviceAuthorizationResponse{Authorization: &clone}, nil
}

func (s *FSDeviceAuthorizationStore) DenyDeviceAuthorization(_ context.Context, req *core.DenyDeviceAuthorizationRequest) (*core.DenyDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, err := s.resolveUserCode(req.UserCode)
	if err != nil {
		return nil, err
	}
	a, err := s.readDeviceCode(dc)
	if err != nil {
		return nil, err
	}
	if a.Status != core.DeviceAuthorizationStatusPending {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	a.Status = core.DeviceAuthorizationStatusDenied
	if err := writeJSON(s.deviceCodePath(a.DeviceCode), a); err != nil {
		return nil, err
	}
	return &core.DenyDeviceAuthorizationResponse{}, nil
}

func (s *FSDeviceAuthorizationStore) UpdatePollingState(_ context.Context, req *core.UpdatePollingStateRequest) (*core.UpdatePollingStateResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.readDeviceCode(req.DeviceCode)
	if err != nil {
		return nil, err
	}
	a.LastPolledAt = req.PolledAt
	if req.SlowDown {
		a.IntervalSeconds += 5
	}
	if err := writeJSON(s.deviceCodePath(a.DeviceCode), a); err != nil {
		return nil, err
	}
	clone := *a
	return &core.UpdatePollingStateResponse{Authorization: &clone}, nil
}

func (s *FSDeviceAuthorizationStore) DeleteDeviceAuthorization(_ context.Context, req *core.DeleteDeviceAuthorizationRequest) (*core.DeleteDeviceAuthorizationResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.readDeviceCode(req.DeviceCode)
	if err != nil {
		return nil, err
	}
	_ = os.Remove(s.userCodePath(a.UserCode))
	if err := os.Remove(s.deviceCodePath(a.DeviceCode)); err != nil {
		return nil, fmt.Errorf("DeleteDeviceAuthorization: remove dc: %w", err)
	}
	return &core.DeleteDeviceAuthorizationResponse{}, nil
}

func (s *FSDeviceAuthorizationStore) CleanupExpired(_ context.Context, _ *core.CleanupExpiredDeviceAuthsRequest) (*core.CleanupExpiredDeviceAuthsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &core.CleanupExpiredDeviceAuthsResponse{Removed: 0}, nil
		}
		return nil, fmt.Errorf("CleanupExpired: readdir: %w", err)
	}
	now := time.Now()
	removed := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "dc-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.dir(), e.Name())
		var a core.DeviceAuthorization
		if err := readJSON(path, &a); err != nil {
			continue
		}
		if a.IsExpired(now) {
			_ = os.Remove(s.userCodePath(a.UserCode))
			if err := os.Remove(path); err == nil {
				removed++
			}
		}
	}
	return &core.CleanupExpiredDeviceAuthsResponse{Removed: removed}, nil
}

// resolveUserCode reads the uc-* pointer file and returns the bound
// device_code. Caller MUST hold the appropriate lock.
func (s *FSDeviceAuthorizationStore) resolveUserCode(userCode string) (string, error) {
	var p userCodePointer
	if err := readJSON(s.userCodePath(userCode), &p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", core.ErrDeviceAuthorizationNotFound
		}
		return "", err
	}
	if p.DeviceCode == "" {
		return "", core.ErrDeviceAuthorizationNotFound
	}
	return p.DeviceCode, nil
}

// readDeviceCode reads the canonical record for the given device_code.
// Caller MUST hold the appropriate lock.
func (s *FSDeviceAuthorizationStore) readDeviceCode(deviceCode string) (*core.DeviceAuthorization, error) {
	var a core.DeviceAuthorization
	if err := readJSON(s.deviceCodePath(deviceCode), &a); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, err
	}
	return &a, nil
}

// writeJSON encodes v to path atomically — write to a temp file in the
// same directory, then rename. Avoids torn writes if the process dies
// mid-encode.
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("encode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close: %w", err)
	}
	return os.Rename(tmpName, path)
}

// readJSON decodes the file at path into v.
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// upperUserCode mirrors core's normalization — exported via the upper
// name in the core package, but redeclared here to avoid importing the
// package-private function. Keeping the rules in sync between the two
// implementations is enforced by tests.
func upperUserCode(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' || c == ' ' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
