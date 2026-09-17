package core

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"sync"
	"time"
)

// ErrPushedRequestNotFound is returned by PushedAuthorizationRequestStore
// lookups and deletes when no record matches the supplied request_uri.
// Distinct from "expired": an expired record may still sit in the store
// until CleanupExpired runs, and the authorization endpoint owes the client
// a different error in each case.
var ErrPushedRequestNotFound = errors.New("pushed authorization request not found")

// PushedRequestURIPrefix is the RFC 9126 §2.2 URN form for a request_uri.
// The spec leaves the format to the server but suggests this shape, and
// using it makes a pushed reference recognizable in logs and in a browser
// URL without revealing anything about the request it stands for.
const PushedRequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// PushedAuthorizationRequest is one authorization request a client pushed
// to the PAR endpoint (RFC 9126) and will later reference by request_uri
// from the browser.
//
// Payload holds the pushed parameters verbatim rather than a parsed struct.
// §2.1 admits "any of the parameters applicable for use at the
// authorization endpoint, including those defined in [RFC6749] as well as
// all applicable extensions", so anything this server does not itself
// understand still has to survive the round trip: RFC 9396
// `authorization_details` JSON and RFC 8707 `resource` are the live cases,
// and keeping large RAR payloads out of the browser URL is much of why
// PAR exists.
//
// ClientID records the client the AS authenticated at the push. §2.2
// requires the request_uri to be bound to that client, which is what stops
// one client from redeeming a reference another client pushed.
//
// Consumed marks a reference whose authorization code has been issued.
// §4 wants a request_uri used once, but explicitly allows a server to
// tolerate a repeated dereference caused by a browser reload. Consumption
// therefore tracks code issuance rather than lookups: the built-in consent
// screen reads the record at least twice (render, then approve), and a
// user who reloads before approving is doing nothing wrong.
type PushedAuthorizationRequest struct {
	RequestURI string     `json:"request_uri"`
	ClientID   string     `json:"client_id"`
	Payload    url.Values `json:"payload"`
	Consumed   bool       `json:"consumed"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

// IsExpired reports whether the reference is past its lifetime. RFC 9126 §4
// requires an expired request_uri to be rejected.
func (p *PushedAuthorizationRequest) IsExpired(now time.Time) bool {
	return !now.Before(p.ExpiresAt)
}

// IsUsable reports whether the reference can still produce an authorization
// code: present, unexpired, and not already redeemed.
func (p *PushedAuthorizationRequest) IsUsable(now time.Time) bool {
	return p != nil && !p.Consumed && !p.IsExpired(now)
}

// CreatePushedAuthorizationRequestRequest carries the record to insert. The
// caller has already generated RequestURI with a CSPRNG and authenticated
// the client.
type CreatePushedAuthorizationRequestRequest struct {
	Request *PushedAuthorizationRequest
}

// CreatePushedAuthorizationRequestResponse echoes the stored record.
type CreatePushedAuthorizationRequestResponse struct {
	Request *PushedAuthorizationRequest
}

// GetPushedAuthorizationRequestRequest looks a record up by its request_uri.
type GetPushedAuthorizationRequestRequest struct {
	RequestURI string
}

// GetPushedAuthorizationRequestResponse wraps the stored record.
type GetPushedAuthorizationRequestResponse struct {
	Request *PushedAuthorizationRequest
}

// ConsumePushedAuthorizationRequestRequest marks a reference redeemed.
type ConsumePushedAuthorizationRequestRequest struct {
	RequestURI string
}

// ConsumePushedAuthorizationRequestResponse is empty.
type ConsumePushedAuthorizationRequestResponse struct{}

// DeletePushedAuthorizationRequestRequest removes a record outright.
type DeletePushedAuthorizationRequestRequest struct {
	RequestURI string
}

// DeletePushedAuthorizationRequestResponse is empty.
type DeletePushedAuthorizationRequestResponse struct{}

// CleanupExpiredPushedRequestsRequest is empty; the call enumerates the
// store and drops anything past its expiry.
type CleanupExpiredPushedRequestsRequest struct{}

// CleanupExpiredPushedRequestsResponse reports how many records went.
type CleanupExpiredPushedRequestsResponse struct {
	Removed int
}

// PushedAuthorizationRequestStore persists RFC 9126 pushed authorization
// requests between the back-channel push and the browser-borne
// authorization request that references them.
//
// Records are short-lived by design. §2.2 puts a typical request_uri
// lifetime between 5 and 600 seconds, so a backend does not need to be
// durable across long outages, but it does need to be shared by every node
// that serves /authorize: a reference pushed to one node and dereferenced
// on another must resolve, which is what an in-process store cannot do.
//
// The store does not enforce single-use. Consume records the fact; the
// authorization endpoint decides when to call it, because only that handler
// knows whether a code was actually issued.
type PushedAuthorizationRequestStore interface {
	// CreatePushedAuthorizationRequest inserts a new record. RequestURI
	// MUST be unique among live records. The caller generates it with a
	// CSPRNG, so a collision is a programmer error and surfaces as a
	// generic error rather than a typed sentinel, matching the
	// AuthorizationCodeStore contract.
	CreatePushedAuthorizationRequest(ctx context.Context, req *CreatePushedAuthorizationRequestRequest) (*CreatePushedAuthorizationRequestResponse, error)

	// GetPushedAuthorizationRequest returns the record for a request_uri
	// or ErrPushedRequestNotFound. It does NOT filter by expiry or
	// consumption: the authorization endpoint checks both so it can tell
	// a client that its reference expired rather than that it never
	// existed.
	GetPushedAuthorizationRequest(ctx context.Context, req *GetPushedAuthorizationRequestRequest) (*GetPushedAuthorizationRequestResponse, error)

	// ConsumePushedAuthorizationRequest marks a record redeemed. Called
	// once an authorization code has been issued against it. Returns
	// ErrPushedRequestNotFound when no record matches.
	//
	// Marking rather than deleting is deliberate: a client that replays a
	// consumed reference should be told its request was already used,
	// which a deleted record cannot distinguish from one that never
	// existed. CleanupExpired reclaims the row afterwards.
	ConsumePushedAuthorizationRequest(ctx context.Context, req *ConsumePushedAuthorizationRequestRequest) (*ConsumePushedAuthorizationRequestResponse, error)

	// DeletePushedAuthorizationRequest removes a record. For callers
	// tearing down an abandoned flow. Returns ErrPushedRequestNotFound
	// when no record matches.
	DeletePushedAuthorizationRequest(ctx context.Context, req *DeletePushedAuthorizationRequestRequest) (*DeletePushedAuthorizationRequestResponse, error)

	// CleanupExpiredPushedRequests drops every record past its expiry,
	// consumed or not. Production deployments run this on a timer; tests
	// call it directly.
	CleanupExpiredPushedRequests(ctx context.Context, req *CleanupExpiredPushedRequestsRequest) (*CleanupExpiredPushedRequestsResponse, error)
}

// InMemoryPushedAuthorizationRequestStore is a process-local
// PushedAuthorizationRequestStore. Records are lost on restart, which
// costs a client one re-push, and are invisible to other processes, which
// breaks any deployment serving /par and /authorize from more than one
// node. Use it for tests, single-process dev, and the in-memory mode of the
// reference server; use a shared backend anywhere else.
type InMemoryPushedAuthorizationRequestStore struct {
	mu    sync.RWMutex
	byURI map[string]*PushedAuthorizationRequest
}

// NewInMemoryPushedAuthorizationRequestStore returns an empty store.
func NewInMemoryPushedAuthorizationRequestStore() *InMemoryPushedAuthorizationRequestStore {
	return &InMemoryPushedAuthorizationRequestStore{byURI: map[string]*PushedAuthorizationRequest{}}
}

func (s *InMemoryPushedAuthorizationRequestStore) CreatePushedAuthorizationRequest(_ context.Context, req *CreatePushedAuthorizationRequestRequest) (*CreatePushedAuthorizationRequestResponse, error) {
	if req == nil || req.Request == nil {
		return nil, errors.New("CreatePushedAuthorizationRequest: request is required")
	}
	r := req.Request
	if r.RequestURI == "" {
		return nil, errors.New("CreatePushedAuthorizationRequest: request_uri is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byURI[r.RequestURI]; ok {
		return nil, errors.New("CreatePushedAuthorizationRequest: request_uri collision")
	}
	s.byURI[r.RequestURI] = clonePushedRequest(r)
	return &CreatePushedAuthorizationRequestResponse{Request: clonePushedRequest(r)}, nil
}

func (s *InMemoryPushedAuthorizationRequestStore) GetPushedAuthorizationRequest(_ context.Context, req *GetPushedAuthorizationRequestRequest) (*GetPushedAuthorizationRequestResponse, error) {
	if req == nil {
		return nil, errors.New("GetPushedAuthorizationRequest: request is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored, ok := s.byURI[req.RequestURI]
	if !ok {
		return nil, ErrPushedRequestNotFound
	}
	return &GetPushedAuthorizationRequestResponse{Request: clonePushedRequest(stored)}, nil
}

func (s *InMemoryPushedAuthorizationRequestStore) ConsumePushedAuthorizationRequest(_ context.Context, req *ConsumePushedAuthorizationRequestRequest) (*ConsumePushedAuthorizationRequestResponse, error) {
	if req == nil {
		return nil, errors.New("ConsumePushedAuthorizationRequest: request is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.byURI[req.RequestURI]
	if !ok {
		return nil, ErrPushedRequestNotFound
	}
	stored.Consumed = true
	return &ConsumePushedAuthorizationRequestResponse{}, nil
}

func (s *InMemoryPushedAuthorizationRequestStore) DeletePushedAuthorizationRequest(_ context.Context, req *DeletePushedAuthorizationRequestRequest) (*DeletePushedAuthorizationRequestResponse, error) {
	if req == nil {
		return nil, errors.New("DeletePushedAuthorizationRequest: request is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byURI[req.RequestURI]; !ok {
		return nil, ErrPushedRequestNotFound
	}
	delete(s.byURI, req.RequestURI)
	return &DeletePushedAuthorizationRequestResponse{}, nil
}

func (s *InMemoryPushedAuthorizationRequestStore) CleanupExpiredPushedRequests(_ context.Context, _ *CleanupExpiredPushedRequestsRequest) (*CleanupExpiredPushedRequestsResponse, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for uri, stored := range s.byURI {
		if stored.IsExpired(now) {
			delete(s.byURI, uri)
			removed++
		}
	}
	return &CleanupExpiredPushedRequestsResponse{Removed: removed}, nil
}

// clonePushedRequest deep-copies a record so a caller holding the returned
// value cannot mutate stored state, and so a later Consume cannot
// retroactively change a copy a caller already read.
func clonePushedRequest(r *PushedAuthorizationRequest) *PushedAuthorizationRequest {
	clone := *r
	if r.Payload != nil {
		// Copy the value slices too: maps.Copy would share them, and a
		// caller appending to one would reach into stored state.
		clone.Payload = url.Values{}
		for k, v := range r.Payload {
			clone.Payload[k] = slices.Clone(v)
		}
	}
	return &clone
}
