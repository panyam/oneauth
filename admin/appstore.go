package admin

import (
	"context"
	"errors"
	"sync"
)

// ErrAppNotFound is returned by AppRegistrationStore.GetApp and DeleteApp
// when the requested client_id does not exist.
var ErrAppNotFound = errors.New("app registration not found")

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
// It is the source of truth for registered apps; AppRegistrar holds a
// hot-path in-memory cache that is hydrated from the store on construction
// and updated on every write.
//
// Backends: InMemoryAppStore (admin/), FSAppStore (stores/fs/, see issue #166),
// GORMAppStore (stores/gorm/, see issue #167).
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
// persistent backend (FS, GORM).
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
