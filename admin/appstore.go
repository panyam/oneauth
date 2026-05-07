package admin

import (
	"errors"
	"sync"
)

// ErrAppNotFound is returned by AppRegistrationStore.GetApp and DeleteApp
// when the requested client_id does not exist.
var ErrAppNotFound = errors.New("app registration not found")

// AppRegistrationStore persists app registration metadata.
//
// It is the source of truth for registered apps; AppRegistrar holds a
// hot-path in-memory cache that is hydrated from the store on construction
// and updated on every write.
//
// Backends: InMemoryAppStore (admin/), FSAppStore (stores/fs/, see issue #166),
// GORMAppStore (stores/gorm/, see issue #167).
type AppRegistrationStore interface {
	// SaveApp inserts or replaces the registration for app.ClientID.
	SaveApp(app *AppRegistration) error

	// GetApp returns the registration for clientID, or ErrAppNotFound.
	GetApp(clientID string) (*AppRegistration, error)

	// ListApps returns every registration in the store. Order is unspecified.
	ListApps() ([]*AppRegistration, error)

	// DeleteApp removes the registration for clientID. Returns ErrAppNotFound
	// if no such registration exists.
	DeleteApp(clientID string) error
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

func (s *InMemoryAppStore) SaveApp(app *AppRegistration) error {
	if app == nil || app.ClientID == "" {
		return errors.New("AppRegistration.ClientID required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *app
	s.apps[app.ClientID] = &clone
	return nil
}

func (s *InMemoryAppStore) GetApp(clientID string) (*AppRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	app, ok := s.apps[clientID]
	if !ok {
		return nil, ErrAppNotFound
	}
	clone := *app
	return &clone, nil
}

func (s *InMemoryAppStore) ListApps() ([]*AppRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*AppRegistration, 0, len(s.apps))
	for _, app := range s.apps {
		clone := *app
		out = append(out, &clone)
	}
	return out, nil
}

func (s *InMemoryAppStore) DeleteApp(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apps[clientID]; !ok {
		return ErrAppNotFound
	}
	delete(s.apps, clientID)
	return nil
}
