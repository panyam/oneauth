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
// Neither file holds the device code, the credential a device polls the
// token endpoint with: the record leaves it out, and the user_code
// pointer holds the record's digest (issue 473). Lookups by device_code
// hash the presented code; lookups by user_code return DeviceCode empty.
// Files written before that still hold the code and keep working; each
// rewrite drops it. A mutex makes approve, deny and polling atomic
// within one process.
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

// deviceDigest is the hex SHA-256 of a device code: core.AtRestKey without
// its "sha256:" prefix. Files and pointers use it, never the code.
func deviceDigest(deviceCode string) string {
	return strings.TrimPrefix(core.AtRestKey(deviceCode), "sha256:")
}

func (s *FSDeviceAuthorizationStore) recordPath(digest string) string {
	return filepath.Join(s.dir(), "dc-"+digest+".json")
}

func (s *FSDeviceAuthorizationStore) userCodePath(userCode string) string {
	upper := core.UpperUserCode(userCode)
	h := sha256.Sum256([]byte(upper))
	return filepath.Join(s.dir(), "uc-"+hex.EncodeToString(h[:])+".json")
}

// CreateDeviceAuthorization writes the record and the user_code pointer.
// A device_code or user_code that already has a file is a generic error,
// matching the in-memory store: both came from a CSPRNG.
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
	d := deviceDigest(a.DeviceCode)
	if _, err := os.Stat(s.recordPath(d)); err == nil {
		return nil, errors.New("CreateDeviceAuthorization: device_code collision")
	}
	if _, err := os.Stat(s.userCodePath(a.UserCode)); err == nil {
		return nil, errors.New("CreateDeviceAuthorization: user_code collision")
	}
	if err := os.MkdirAll(s.dir(), 0o700); err != nil {
		return nil, fmt.Errorf("CreateDeviceAuthorization: mkdir: %w", err)
	}
	if err := s.writeRecord(d, a); err != nil {
		return nil, err
	}
	if err := writeJSON(s.userCodePath(a.UserCode), userCodePointer{DeviceDigest: d}); err != nil {
		// Best-effort rollback so a failed create leaves no record behind.
		_ = os.Remove(s.recordPath(d))
		return nil, err
	}
	return &core.CreateDeviceAuthorizationResponse{}, nil
}

// userCodePointer is the small file at uc-<hash>.json that resolves a
// user_code to its record. DeviceDigest names the record. DeviceCode is
// only read, from pointers written before issue 473 stored the code
// itself; it is hashed on read.
type userCodePointer struct {
	DeviceDigest string `json:"device_digest,omitempty"`
	DeviceCode   string `json:"device_code,omitempty"`
}

// GetByDeviceCode returns the record, with DeviceCode filled in from the
// request, or core.ErrDeviceAuthorizationNotFound. It doesn't filter by
// status or expiry.
func (s *FSDeviceAuthorizationStore) GetByDeviceCode(_ context.Context, req *core.GetByDeviceCodeRequest) (*core.GetByDeviceCodeResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, err := s.readRecord(deviceDigest(req.DeviceCode))
	if err != nil {
		return nil, err
	}
	a.DeviceCode = req.DeviceCode
	return &core.GetByDeviceCodeResponse{Authorization: a}, nil
}

// GetByUserCode returns the record with DeviceCode empty (see
// core.DeviceAuthorizationStore), or core.ErrDeviceAuthorizationNotFound.
func (s *FSDeviceAuthorizationStore) GetByUserCode(_ context.Context, req *core.GetByUserCodeRequest) (*core.GetByUserCodeResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, err := s.resolveUserCode(req.UserCode)
	if err != nil {
		return nil, err
	}
	a, err := s.readRecord(d)
	if err != nil {
		return nil, err
	}
	return &core.GetByUserCodeResponse{Authorization: a}, nil
}

// ApproveDeviceAuthorization moves a pending record to approved under the
// store's lock, so of racing approvals and denials exactly one succeeds.
// The returned authorization's DeviceCode is empty.
func (s *FSDeviceAuthorizationStore) ApproveDeviceAuthorization(_ context.Context, req *core.ApproveDeviceAuthorizationRequest) (*core.ApproveDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.resolveUserCode(req.UserCode)
	if err != nil {
		return nil, err
	}
	a, err := s.readRecord(d)
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
	if err := s.writeRecord(d, a); err != nil {
		return nil, err
	}
	clone := *a
	return &core.ApproveDeviceAuthorizationResponse{Authorization: &clone}, nil
}

// DenyDeviceAuthorization moves a pending record to denied under the
// store's lock.
func (s *FSDeviceAuthorizationStore) DenyDeviceAuthorization(_ context.Context, req *core.DenyDeviceAuthorizationRequest) (*core.DenyDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.resolveUserCode(req.UserCode)
	if err != nil {
		return nil, err
	}
	a, err := s.readRecord(d)
	if err != nil {
		return nil, err
	}
	if a.Status != core.DeviceAuthorizationStatusPending {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	a.Status = core.DeviceAuthorizationStatusDenied
	if err := s.writeRecord(d, a); err != nil {
		return nil, err
	}
	return &core.DenyDeviceAuthorizationResponse{}, nil
}

// UpdatePollingState records a poll and returns the record with
// DeviceCode filled in from the request.
func (s *FSDeviceAuthorizationStore) UpdatePollingState(_ context.Context, req *core.UpdatePollingStateRequest) (*core.UpdatePollingStateResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := deviceDigest(req.DeviceCode)
	a, err := s.readRecord(d)
	if err != nil {
		return nil, err
	}
	a.LastPolledAt = req.PolledAt
	if req.SlowDown {
		a.IntervalSeconds += 5
	}
	if err := s.writeRecord(d, a); err != nil {
		return nil, err
	}
	clone := *a
	clone.DeviceCode = req.DeviceCode
	return &core.UpdatePollingStateResponse{Authorization: &clone}, nil
}

// DeleteDeviceAuthorization removes the record and its user_code pointer,
// or returns core.ErrDeviceAuthorizationNotFound.
func (s *FSDeviceAuthorizationStore) DeleteDeviceAuthorization(_ context.Context, req *core.DeleteDeviceAuthorizationRequest) (*core.DeleteDeviceAuthorizationResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := deviceDigest(req.DeviceCode)
	a, err := s.readRecord(d)
	if err != nil {
		return nil, err
	}
	_ = os.Remove(s.userCodePath(a.UserCode))
	if err := os.Remove(s.recordPath(d)); err != nil {
		return nil, fmt.Errorf("DeleteDeviceAuthorization: remove dc: %w", err)
	}
	return &core.DeleteDeviceAuthorizationResponse{}, nil
}

// CleanupExpired removes every expired record and its user_code pointer.
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

// resolveUserCode reads the uc-* pointer and returns the record's digest.
// Caller MUST hold the appropriate lock.
func (s *FSDeviceAuthorizationStore) resolveUserCode(userCode string) (string, error) {
	var p userCodePointer
	if err := readJSON(s.userCodePath(userCode), &p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", core.ErrDeviceAuthorizationNotFound
		}
		return "", err
	}
	switch {
	case p.DeviceDigest != "":
		return p.DeviceDigest, nil
	case p.DeviceCode != "":
		return deviceDigest(p.DeviceCode), nil
	}
	return "", core.ErrDeviceAuthorizationNotFound
}

// readRecord reads the record named by digest, with DeviceCode empty even
// for a file written before issue 473 that still holds it. Caller MUST
// hold the appropriate lock.
func (s *FSDeviceAuthorizationStore) readRecord(digest string) (*core.DeviceAuthorization, error) {
	var a core.DeviceAuthorization
	if err := readJSON(s.recordPath(digest), &a); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, err
	}
	a.DeviceCode = ""
	return &a, nil
}

// writeRecord stores a without its device code, so a rewrite of an old
// file drops the plaintext too.
func (s *FSDeviceAuthorizationStore) writeRecord(digest string, a *core.DeviceAuthorization) error {
	out := *a
	out.DeviceCode = ""
	return writeJSON(s.recordPath(digest), &out)
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
