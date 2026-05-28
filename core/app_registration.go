package core

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrAppNotFound is returned by AppRegistrationStore.GetApp and DeleteApp
// when the requested client_id does not exist.
var ErrAppNotFound = errors.New("app registration not found")

// AppRegistration holds metadata about a registered App (RFC 7591 client).
//
// Lives in core/ so storage backends (stores/fs, stores/gorm, stores/gae) can
// implement AppRegistrationStore without importing admin/. The DCR / RFC 7592
// management metadata fields are persisted starting in issue 165 so that the
// schema is stable as RFC 7592 management endpoints (issue 168/169/170) populate
// them. They may be empty for legacy registrations.
type AppRegistration struct {
	ClientID                  string    `json:"client_id"`
	ClientDomain              string    `json:"client_domain"`
	SigningAlg                string    `json:"signing_alg"`
	AuthorizationDetailsTypes []string  `json:"authorization_details_types,omitempty"` // RFC 9396
	CreatedAt                 time.Time `json:"created_at"`
	Revoked                   bool      `json:"revoked"`

	// RFC 7591 / 7592 client metadata (populated by DCR; see issue 157).
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`

	// RFC 7592 management credentials. Issued when the management protocol
	// is implemented (issue 168); empty for legacy registrations.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// SaveAppRequest carries the registration to persist.
type SaveAppRequest struct {
	App *AppRegistration
}

// SaveAppResponse is empty; SaveApp returns only an error signal.
type SaveAppResponse struct{}

// GetAppRequest carries the client_id to look up.
type GetAppRequest struct {
	ClientID string
}

// GetAppResponse wraps the requested registration.
type GetAppResponse struct {
	App *AppRegistration
}

// ListAppsRequest is empty; ListApps takes no parameters.
type ListAppsRequest struct{}

// ListAppsResponse wraps every registration in the store. Order is unspecified.
type ListAppsResponse struct {
	Apps []*AppRegistration
}

// DeleteAppRequest carries the client_id to remove.
type DeleteAppRequest struct {
	ClientID string
}

// DeleteAppResponse is empty; DeleteApp returns only an error signal.
type DeleteAppResponse struct{}

// AppRegistrationStore persists app registration metadata.
//
// Source of truth for registered apps; admin.AppRegistrar holds a hot-path
// in-memory cache that is hydrated from the store on construction and updated
// on every write.
//
// Backends: InMemoryAppStore (below), FSAppStore (stores/fs/), GORMAppStore
// (stores/gorm/), and any future Datastore-backed implementation (issue 228).
type AppRegistrationStore interface {
	// SaveApp inserts or replaces the registration for req.App.ClientID.
	SaveApp(ctx context.Context, req *SaveAppRequest) (*SaveAppResponse, error)

	// GetApp returns the registration for req.ClientID, or ErrAppNotFound.
	GetApp(ctx context.Context, req *GetAppRequest) (*GetAppResponse, error)

	// ListApps returns every registration in the store. Order is unspecified.
	ListApps(ctx context.Context, req *ListAppsRequest) (*ListAppsResponse, error)

	// DeleteApp removes the registration for req.ClientID. Returns ErrAppNotFound
	// if no such registration exists.
	DeleteApp(ctx context.Context, req *DeleteAppRequest) (*DeleteAppResponse, error)
}

// InMemoryAppStore is a process-local AppRegistrationStore. State is lost on
// restart — suitable for tests and dev. Production deployments should use a
// persistent backend (FS, GORM, GAE).
type InMemoryAppStore struct {
	mu   sync.RWMutex
	apps map[string]*AppRegistration
}

// NewInMemoryAppStore returns an empty InMemoryAppStore.
func NewInMemoryAppStore() *InMemoryAppStore {
	return &InMemoryAppStore{apps: make(map[string]*AppRegistration)}
}

func (s *InMemoryAppStore) SaveApp(ctx context.Context, req *SaveAppRequest) (*SaveAppResponse, error) {
	if req == nil || req.App == nil || req.App.ClientID == "" {
		return nil, errors.New("AppRegistration.ClientID required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *req.App
	s.apps[req.App.ClientID] = &clone
	return &SaveAppResponse{}, nil
}

func (s *InMemoryAppStore) GetApp(ctx context.Context, req *GetAppRequest) (*GetAppResponse, error) {
	if req == nil {
		return nil, errors.New("GetApp: req is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	app, ok := s.apps[req.ClientID]
	if !ok {
		return nil, ErrAppNotFound
	}
	clone := *app
	return &GetAppResponse{App: &clone}, nil
}

func (s *InMemoryAppStore) ListApps(ctx context.Context, req *ListAppsRequest) (*ListAppsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*AppRegistration, 0, len(s.apps))
	for _, app := range s.apps {
		clone := *app
		out = append(out, &clone)
	}
	return &ListAppsResponse{Apps: out}, nil
}

func (s *InMemoryAppStore) DeleteApp(ctx context.Context, req *DeleteAppRequest) (*DeleteAppResponse, error) {
	if req == nil {
		return nil, errors.New("DeleteApp: req is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apps[req.ClientID]; !ok {
		return nil, ErrAppNotFound
	}
	delete(s.apps, req.ClientID)
	return &DeleteAppResponse{}, nil
}
