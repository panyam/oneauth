package core

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrDeviceAuthorizationNotFound is returned when a lookup by device_code,
// user_code, or both fails to find a record. Distinct from "expired" — an
// expired record may still exist in the store until CleanupExpired runs,
// and callers may want to surface a different error to the caller in each
// case.
var ErrDeviceAuthorizationNotFound = errors.New("device authorization not found")

// DeviceAuthorizationStatus is the lifecycle state of an RFC 8628 device
// authorization request. The token endpoint maps status to the polling
// error response: Pending → authorization_pending, Denied → access_denied,
// Expired → expired_token. Approved is the only state that yields an
// access token.
type DeviceAuthorizationStatus string

const (
	// DeviceAuthorizationStatusPending means the user has not yet visited
	// the verification URI (or has visited but not approved). Polling
	// returns `authorization_pending`.
	DeviceAuthorizationStatusPending DeviceAuthorizationStatus = "pending"

	// DeviceAuthorizationStatusApproved means the user approved the
	// authorization. The next successful poll yields an access token; the
	// device authorization is consumed (deleted) on a successful token
	// exchange to prevent replay.
	DeviceAuthorizationStatusApproved DeviceAuthorizationStatus = "approved"

	// DeviceAuthorizationStatusDenied means the user explicitly rejected
	// the authorization. Polling returns `access_denied`.
	DeviceAuthorizationStatusDenied DeviceAuthorizationStatus = "denied"
)

// DeviceAuthorization is one RFC 8628 §3.1 device authorization request.
// device_code and user_code are independent identifiers — the device polls
// by device_code, the user enters user_code on the verification URI.
type DeviceAuthorization struct {
	// DeviceCode is the high-entropy identifier the device polls with.
	// 256-bit, hex-encoded; unguessable.
	DeviceCode string `json:"device_code"`

	// UserCode is the short, human-typeable identifier the user enters on
	// the verification URI. RFC 8628 §6.1 recommends a constrained
	// charset; this implementation uses 8 chars from
	// BCDEFGHJKLMNPQRSTVWXZ23456789 (ambiguity-resistant).
	UserCode string `json:"user_code"`

	// ClientID is the OAuth client that initiated the device flow.
	ClientID string `json:"client_id"`

	// Scopes is the scope set requested at /device/authorize. Carried
	// forward unchanged to the issued access token.
	Scopes []string `json:"scopes,omitempty"`

	// RequestedAudience captures an optional RFC 8707 `audience` parameter
	// the device passed at /device/authorize. Empty when not requested.
	RequestedAudience string `json:"requested_audience,omitempty"`

	// Status tracks the lifecycle. See DeviceAuthorizationStatus values.
	Status DeviceAuthorizationStatus `json:"status"`

	// ApprovedSubject is the user (RFC 7519 `sub`) who approved this
	// authorization. Populated only when Status == Approved.
	ApprovedSubject string `json:"approved_subject,omitempty"`

	// CreatedAt is when the device authorization was created. Pinned at
	// creation time so polling-interval enforcement can reason from it.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is the deadline after which a polling request returns
	// expired_token. RFC 8628 §3.4 recommends 15 minutes.
	ExpiresAt time.Time `json:"expires_at"`

	// LastPolledAt is the last time the device polled the token endpoint
	// with this device_code. Used to enforce the `interval` rate limit and
	// emit `slow_down`.
	LastPolledAt time.Time `json:"last_polled_at,omitempty"`

	// IntervalSeconds is the current minimum polling interval the device
	// MUST respect. Starts at the AS default (5s per RFC 8628 §3.5) and
	// may grow when the AS emits `slow_down`.
	IntervalSeconds int `json:"interval_seconds"`
}

// IsExpired reports whether the authorization is past its deadline.
// Centralized here so the store, the grant handler, and the cleanup pass
// agree on the comparison.
func (d *DeviceAuthorization) IsExpired(now time.Time) bool {
	return !d.ExpiresAt.IsZero() && !now.Before(d.ExpiresAt)
}

// CreateDeviceAuthorizationRequest carries the inputs for persisting a
// freshly-minted device authorization. The handler computes the codes,
// status, and timestamps; the store persists.
type CreateDeviceAuthorizationRequest struct {
	Authorization *DeviceAuthorization
}

// CreateDeviceAuthorizationResponse is empty — CreateDeviceAuthorization
// returns success/failure via the error.
type CreateDeviceAuthorizationResponse struct{}

// GetByDeviceCodeRequest carries the device_code to look up.
type GetByDeviceCodeRequest struct {
	DeviceCode string
}

// GetByDeviceCodeResponse wraps the requested authorization.
type GetByDeviceCodeResponse struct {
	Authorization *DeviceAuthorization
}

// GetByUserCodeRequest carries the user_code to look up. user_code is
// case-insensitive per RFC 8628 §3.2; the store implementation normalizes
// to upper-case before comparison.
type GetByUserCodeRequest struct {
	UserCode string
}

// GetByUserCodeResponse wraps the requested authorization.
type GetByUserCodeResponse struct {
	Authorization *DeviceAuthorization
}

// ApproveDeviceAuthorizationRequest carries the user_code the user
// entered plus the subject and scopes that should be bound to the
// resulting access token. The store transitions Status to Approved.
type ApproveDeviceAuthorizationRequest struct {
	UserCode        string
	ApprovedSubject string
	GrantedScopes   []string // optional — overrides Authorization.Scopes when non-nil (consent UI may narrow scope)
}

// ApproveDeviceAuthorizationResponse wraps the updated authorization so
// callers (e.g. a UI handler that renders a "you may now return to your
// device" page) can read the subject + scope set that was bound.
type ApproveDeviceAuthorizationResponse struct {
	Authorization *DeviceAuthorization
}

// DenyDeviceAuthorizationRequest carries the user_code the user entered
// when refusing the authorization.
type DenyDeviceAuthorizationRequest struct {
	UserCode string
}

// DenyDeviceAuthorizationResponse is empty.
type DenyDeviceAuthorizationResponse struct{}

// UpdatePollingStateRequest records that a device just polled. The store
// updates LastPolledAt and, when SlowDown is true, raises IntervalSeconds
// by 5 (RFC 8628 §3.5).
type UpdatePollingStateRequest struct {
	DeviceCode string
	PolledAt   time.Time
	SlowDown   bool
}

// UpdatePollingStateResponse wraps the updated authorization.
type UpdatePollingStateResponse struct {
	Authorization *DeviceAuthorization
}

// DeleteDeviceAuthorizationRequest carries the device_code to remove. The
// grant handler deletes after a successful token exchange so the same
// device_code cannot be replayed for a second access token.
type DeleteDeviceAuthorizationRequest struct {
	DeviceCode string
}

// DeleteDeviceAuthorizationResponse is empty.
type DeleteDeviceAuthorizationResponse struct{}

// CleanupExpiredDeviceAuthsRequest is empty; the call enumerates the
// store and removes anything past its expiry.
type CleanupExpiredDeviceAuthsRequest struct{}

// CleanupExpiredDeviceAuthsResponse reports how many records were
// removed. Useful for telemetry / log-line metrics.
type CleanupExpiredDeviceAuthsResponse struct {
	Removed int
}

// DeviceAuthorizationStore persists RFC 8628 device authorization state.
//
// Backends ship in lock-step with the other store interfaces:
// InMemoryDeviceAuthorizationStore (below), FSDeviceAuthorizationStore
// (stores/fs/). GORM and GAE backends are deferred to follow-ups under
// the same precedent as AppRegistrationStore.
//
// Lookups by user_code MUST be case-insensitive (RFC 8628 §3.2) — users
// enter the code by hand and shift state is irrelevant. Stores normalize
// to upper-case before comparison.
type DeviceAuthorizationStore interface {
	// CreateDeviceAuthorization inserts a new device authorization.
	// device_code and user_code MUST be unique across all non-expired
	// records — the caller has already generated them via cryptographic
	// RNG, so a collision is a programmer error and surfaces as a
	// generic error (not a typed sentinel).
	CreateDeviceAuthorization(ctx context.Context, req *CreateDeviceAuthorizationRequest) (*CreateDeviceAuthorizationResponse, error)

	// GetByDeviceCode returns the authorization for the given device_code,
	// or ErrDeviceAuthorizationNotFound. Does NOT filter by status or
	// expiry — the caller (the token endpoint handler) checks both.
	GetByDeviceCode(ctx context.Context, req *GetByDeviceCodeRequest) (*GetByDeviceCodeResponse, error)

	// GetByUserCode returns the authorization for the given user_code (case-
	// insensitive comparison), or ErrDeviceAuthorizationNotFound.
	GetByUserCode(ctx context.Context, req *GetByUserCodeRequest) (*GetByUserCodeResponse, error)

	// ApproveDeviceAuthorization transitions a pending authorization to
	// approved and binds the subject + scopes that the user consented to.
	// Returns ErrDeviceAuthorizationNotFound when no pending record matches
	// user_code.
	ApproveDeviceAuthorization(ctx context.Context, req *ApproveDeviceAuthorizationRequest) (*ApproveDeviceAuthorizationResponse, error)

	// DenyDeviceAuthorization transitions a pending authorization to
	// denied. Returns ErrDeviceAuthorizationNotFound when no pending
	// record matches user_code.
	DenyDeviceAuthorization(ctx context.Context, req *DenyDeviceAuthorizationRequest) (*DenyDeviceAuthorizationResponse, error)

	// UpdatePollingState records a poll attempt. Always updates
	// LastPolledAt; raises IntervalSeconds by 5 when SlowDown is true.
	UpdatePollingState(ctx context.Context, req *UpdatePollingStateRequest) (*UpdatePollingStateResponse, error)

	// DeleteDeviceAuthorization removes the authorization. Used by the
	// token endpoint on successful exchange (prevents replay) and by
	// callers cleaning up rejected flows. Returns
	// ErrDeviceAuthorizationNotFound when no record matches.
	DeleteDeviceAuthorization(ctx context.Context, req *DeleteDeviceAuthorizationRequest) (*DeleteDeviceAuthorizationResponse, error)

	// CleanupExpired enumerates the store and removes every record whose
	// ExpiresAt is at or before the current wall-clock time. Production
	// deployments run this on a timer; tests call it explicitly.
	CleanupExpired(ctx context.Context, req *CleanupExpiredDeviceAuthsRequest) (*CleanupExpiredDeviceAuthsResponse, error)
}

// InMemoryDeviceAuthorizationStore is a process-local
// DeviceAuthorizationStore. State is lost on restart — suitable for
// tests, single-process dev, and the in-memory mode of the reference
// server. Production deployments use a persistent backend.
type InMemoryDeviceAuthorizationStore struct {
	mu              sync.RWMutex
	byDeviceCode    map[string]*DeviceAuthorization
	byUserCodeUpper map[string]string // upper(user_code) → device_code
}

// NewInMemoryDeviceAuthorizationStore returns an empty store.
func NewInMemoryDeviceAuthorizationStore() *InMemoryDeviceAuthorizationStore {
	return &InMemoryDeviceAuthorizationStore{
		byDeviceCode:    map[string]*DeviceAuthorization{},
		byUserCodeUpper: map[string]string{},
	}
}

func (s *InMemoryDeviceAuthorizationStore) CreateDeviceAuthorization(_ context.Context, req *CreateDeviceAuthorizationRequest) (*CreateDeviceAuthorizationResponse, error) {
	if req == nil || req.Authorization == nil {
		return nil, errors.New("CreateDeviceAuthorization: authorization is required")
	}
	a := req.Authorization
	if a.DeviceCode == "" || a.UserCode == "" {
		return nil, errors.New("CreateDeviceAuthorization: device_code and user_code are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	upper := UpperUserCode(a.UserCode)
	if _, ok := s.byDeviceCode[a.DeviceCode]; ok {
		return nil, errors.New("CreateDeviceAuthorization: device_code collision")
	}
	if _, ok := s.byUserCodeUpper[upper]; ok {
		return nil, errors.New("CreateDeviceAuthorization: user_code collision")
	}
	clone := *a
	s.byDeviceCode[a.DeviceCode] = &clone
	s.byUserCodeUpper[upper] = a.DeviceCode
	return &CreateDeviceAuthorizationResponse{}, nil
}

func (s *InMemoryDeviceAuthorizationStore) GetByDeviceCode(_ context.Context, req *GetByDeviceCodeRequest) (*GetByDeviceCodeResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, ErrDeviceAuthorizationNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.byDeviceCode[req.DeviceCode]
	if !ok {
		return nil, ErrDeviceAuthorizationNotFound
	}
	clone := *a
	return &GetByDeviceCodeResponse{Authorization: &clone}, nil
}

func (s *InMemoryDeviceAuthorizationStore) GetByUserCode(_ context.Context, req *GetByUserCodeRequest) (*GetByUserCodeResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, ErrDeviceAuthorizationNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	dc, ok := s.byUserCodeUpper[UpperUserCode(req.UserCode)]
	if !ok {
		return nil, ErrDeviceAuthorizationNotFound
	}
	a := s.byDeviceCode[dc]
	if a == nil {
		return nil, ErrDeviceAuthorizationNotFound
	}
	clone := *a
	return &GetByUserCodeResponse{Authorization: &clone}, nil
}

func (s *InMemoryDeviceAuthorizationStore) ApproveDeviceAuthorization(_ context.Context, req *ApproveDeviceAuthorizationRequest) (*ApproveDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.byUserCodeUpper[UpperUserCode(req.UserCode)]
	if !ok {
		return nil, ErrDeviceAuthorizationNotFound
	}
	a := s.byDeviceCode[dc]
	if a == nil || a.Status != DeviceAuthorizationStatusPending {
		return nil, ErrDeviceAuthorizationNotFound
	}
	a.Status = DeviceAuthorizationStatusApproved
	a.ApprovedSubject = req.ApprovedSubject
	if req.GrantedScopes != nil {
		a.Scopes = req.GrantedScopes
	}
	clone := *a
	return &ApproveDeviceAuthorizationResponse{Authorization: &clone}, nil
}

func (s *InMemoryDeviceAuthorizationStore) DenyDeviceAuthorization(_ context.Context, req *DenyDeviceAuthorizationRequest) (*DenyDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.byUserCodeUpper[UpperUserCode(req.UserCode)]
	if !ok {
		return nil, ErrDeviceAuthorizationNotFound
	}
	a := s.byDeviceCode[dc]
	if a == nil || a.Status != DeviceAuthorizationStatusPending {
		return nil, ErrDeviceAuthorizationNotFound
	}
	a.Status = DeviceAuthorizationStatusDenied
	return &DenyDeviceAuthorizationResponse{}, nil
}

func (s *InMemoryDeviceAuthorizationStore) UpdatePollingState(_ context.Context, req *UpdatePollingStateRequest) (*UpdatePollingStateResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byDeviceCode[req.DeviceCode]
	if !ok {
		return nil, ErrDeviceAuthorizationNotFound
	}
	a.LastPolledAt = req.PolledAt
	if req.SlowDown {
		a.IntervalSeconds += 5
	}
	clone := *a
	return &UpdatePollingStateResponse{Authorization: &clone}, nil
}

func (s *InMemoryDeviceAuthorizationStore) DeleteDeviceAuthorization(_ context.Context, req *DeleteDeviceAuthorizationRequest) (*DeleteDeviceAuthorizationResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, ErrDeviceAuthorizationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byDeviceCode[req.DeviceCode]
	if !ok {
		return nil, ErrDeviceAuthorizationNotFound
	}
	delete(s.byDeviceCode, req.DeviceCode)
	delete(s.byUserCodeUpper, UpperUserCode(a.UserCode))
	return &DeleteDeviceAuthorizationResponse{}, nil
}

func (s *InMemoryDeviceAuthorizationStore) CleanupExpired(_ context.Context, _ *CleanupExpiredDeviceAuthsRequest) (*CleanupExpiredDeviceAuthsResponse, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for dc, a := range s.byDeviceCode {
		if a.IsExpired(now) {
			delete(s.byDeviceCode, dc)
			delete(s.byUserCodeUpper, UpperUserCode(a.UserCode))
			removed++
		}
	}
	return &CleanupExpiredDeviceAuthsResponse{Removed: removed}, nil
}

// UpperUserCode normalizes an RFC 8628 user_code to the canonical
// store-key form: dashes and spaces stripped, ASCII letters folded to
// upper case. The display form keeps a dash (XXXX-XXXX) so the printable
// code stays readable on the device's screen, but every store backend
// indexes on the normalized form so the user can paste either variant
// into the verification page and still hit the same record.
//
// RFC 8628 §6.1 leaves user-facing display formatting to the
// verification UI; the server-side normalization rule is OneAuth's
// contract — every DeviceAuthorizationStore implementation calls this
// helper on both the write path (Create) and every read path
// (GetByUserCode / Approve / Deny). Adding a new backend? Use this
// function — do not roll your own.
//
// Pure / safe for concurrent use.
func UpperUserCode(s string) string {
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
