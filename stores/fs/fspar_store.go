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

// FSPushedAuthorizationRequestStore keeps RFC 9126 pushed authorization
// requests as one JSON file each under
// <StoragePath>/pushed_authorization_requests/.
//
// Files are named by core.AtRestKey(request_uri) and the JSON leaves the
// request_uri out, so a copy of the directory can't be used to start an
// authorization. The payload is stored as url.Values, so extension
// parameters and authorization_details JSON round-trip verbatim.
//
// A mutex makes ConsumePushedAuthorizationRequest's check-and-mark atomic
// within one process. Replicas need the GORM or GAE store.
type FSPushedAuthorizationRequestStore struct {
	StoragePath string

	mu sync.Mutex
}

// NewFSPushedAuthorizationRequestStore returns a store rooted at
// storagePath. The directory is created on first write.
func NewFSPushedAuthorizationRequestStore(storagePath string) *FSPushedAuthorizationRequestStore {
	return &FSPushedAuthorizationRequestStore{StoragePath: storagePath}
}

func (s *FSPushedAuthorizationRequestStore) dir() string {
	return filepath.Join(s.StoragePath, "pushed_authorization_requests")
}

func (s *FSPushedAuthorizationRequestStore) path(uri string) string {
	return filepath.Join(s.dir(), atRestFileName(uri))
}

// read loads uri's record, with RequestURI filled back in from the
// argument. A missing file is core.ErrPushedRequestNotFound.
func (s *FSPushedAuthorizationRequestStore) read(uri string) (*core.PushedAuthorizationRequest, error) {
	data, err := os.ReadFile(s.path(uri))
	if errors.Is(err, os.ErrNotExist) {
		return nil, core.ErrPushedRequestNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec core.PushedAuthorizationRequest
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("fs: pushed request file: %w", err)
	}
	rec.RequestURI = uri
	return &rec, nil
}

func (s *FSPushedAuthorizationRequestStore) write(rec *core.PushedAuthorizationRequest) error {
	out := *rec
	out.RequestURI = ""
	data, err := json.Marshal(&out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir(), 0o700); err != nil {
		return err
	}
	return writeAtomicFile(s.path(rec.RequestURI), data)
}

// CreatePushedAuthorizationRequest stores a new request and returns it. A
// request_uri that already has a file is a generic error, matching the
// in-memory store.
func (s *FSPushedAuthorizationRequestStore) CreatePushedAuthorizationRequest(_ context.Context, req *core.CreatePushedAuthorizationRequestRequest) (*core.CreatePushedAuthorizationRequestResponse, error) {
	if req == nil || req.Request == nil || req.Request.RequestURI == "" {
		return nil, errors.New("CreatePushedAuthorizationRequest: request_uri is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(s.path(req.Request.RequestURI)); err == nil {
		return nil, errors.New("CreatePushedAuthorizationRequest: request_uri collision")
	}
	r := req.Request
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	if err := s.write(r); err != nil {
		return nil, err
	}
	return &core.CreatePushedAuthorizationRequestResponse{Request: r}, nil
}

// GetPushedAuthorizationRequest returns the record or
// core.ErrPushedRequestNotFound. It doesn't filter by expiry or
// consumption, so /authorize can tell a client its reference expired or
// was used rather than that it never existed.
func (s *FSPushedAuthorizationRequestStore) GetPushedAuthorizationRequest(_ context.Context, req *core.GetPushedAuthorizationRequestRequest) (*core.GetPushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.read(req.RequestURI)
	if err != nil {
		return nil, err
	}
	return &core.GetPushedAuthorizationRequestResponse{Request: rec}, nil
}

// ConsumePushedAuthorizationRequest marks the request used and keeps the
// file, so a replay reads back as used rather than unknown. Consumed is
// true for exactly one caller. A missing request is
// core.ErrPushedRequestNotFound.
func (s *FSPushedAuthorizationRequestStore) ConsumePushedAuthorizationRequest(_ context.Context, req *core.ConsumePushedAuthorizationRequestRequest) (*core.ConsumePushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.read(req.RequestURI)
	if err != nil {
		return nil, err
	}
	if rec.Consumed {
		return &core.ConsumePushedAuthorizationRequestResponse{Consumed: false}, nil
	}
	rec.Consumed = true
	if err := s.write(rec); err != nil {
		return nil, err
	}
	return &core.ConsumePushedAuthorizationRequestResponse{Consumed: true}, nil
}

// DeletePushedAuthorizationRequest removes the file, or returns
// core.ErrPushedRequestNotFound when there is none.
func (s *FSPushedAuthorizationRequestStore) DeletePushedAuthorizationRequest(_ context.Context, req *core.DeletePushedAuthorizationRequestRequest) (*core.DeletePushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(req.RequestURI))
	if errors.Is(err, os.ErrNotExist) {
		return nil, core.ErrPushedRequestNotFound
	}
	if err != nil {
		return nil, err
	}
	return &core.DeletePushedAuthorizationRequestResponse{}, nil
}

// CleanupExpiredPushedRequests removes every request past its ExpiresAt,
// consumed or not, so used requests don't pile up. A file that won't
// parse is left alone.
func (s *FSPushedAuthorizationRequestStore) CleanupExpiredPushedRequests(_ context.Context, _ *core.CleanupExpiredPushedRequestsRequest) (*core.CleanupExpiredPushedRequestsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir())
	if errors.Is(err, os.ErrNotExist) {
		return &core.CleanupExpiredPushedRequestsResponse{}, nil
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
		var rec core.PushedAuthorizationRequest
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		if !now.Before(rec.ExpiresAt) {
			if os.Remove(p) == nil {
				removed++
			}
		}
	}
	return &core.CleanupExpiredPushedRequestsResponse{Removed: removed}, nil
}

var _ core.PushedAuthorizationRequestStore = (*FSPushedAuthorizationRequestStore)(nil)
