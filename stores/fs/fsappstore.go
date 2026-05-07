package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/panyam/oneauth/admin"
)

// FSAppStore implements admin.AppRegistrationStore by persisting each
// registration as a JSON file under {basePath}/apps/{client_id}.json.
//
// Mirrors the FSKeyStore design: file-per-record (so concurrent ops don't
// serialize on a single mutex outside this process), atomic writes via
// temp-file + rename (so a crash mid-write leaves either the old file or
// the new file intact, never a half-written one), and safeName guarding
// path-traversal in client_ids.
//
// In-process concurrency is mediated by sync.RWMutex. Multi-process
// deployments need a backend with real transaction semantics — see
// GORMAppStore (#167).
type FSAppStore struct {
	StoragePath string
	mu          sync.RWMutex
}

// NewFSAppStore creates a filesystem-backed AppRegistrationStore. The
// {basePath}/apps/ directory is created lazily on first write.
func NewFSAppStore(storagePath string) *FSAppStore {
	return &FSAppStore{StoragePath: storagePath}
}

func (s *FSAppStore) appsDir() string {
	return filepath.Join(s.StoragePath, "apps")
}

func (s *FSAppStore) appPath(clientID string) (string, error) {
	safeID, err := safeName(clientID)
	if err != nil {
		return "", fmt.Errorf("invalid clientID: %w", err)
	}
	return filepath.Join(s.appsDir(), safeID+".json"), nil
}

// SaveApp persists app to disk. Overwrites any existing registration with
// the same client_id. Empty client_id is rejected.
func (s *FSAppStore) SaveApp(app *admin.AppRegistration) error {
	if app == nil || app.ClientID == "" {
		return fmt.Errorf("AppRegistration.ClientID required")
	}

	path, err := s.appPath(app.ClientID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.appsDir(), 0700); err != nil {
		return fmt.Errorf("create apps dir: %w", err)
	}

	data, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal AppRegistration: %w", err)
	}
	return writeAtomicFile(path, data)
}

// GetApp returns the registration for clientID, or admin.ErrAppNotFound if
// no such file exists. A corrupt JSON file surfaces as a parse error rather
// than ErrAppNotFound — callers should distinguish "registration absent"
// from "registration unreadable" so an unexpected on-disk corruption isn't
// silently treated as a missing client.
func (s *FSAppStore) GetApp(clientID string) (*admin.AppRegistration, error) {
	path, err := s.appPath(clientID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, admin.ErrAppNotFound
		}
		return nil, err
	}
	var app admin.AppRegistration
	if err := json.Unmarshal(data, &app); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return &app, nil
}

// ListApps returns every registration in the store. Files that fail to
// parse are skipped (with no error returned) so a single hand-corrupted
// file does not lock out admin tooling — partial recovery beats total
// failure here. Callers needing strict integrity should validate at the
// store level (e.g., periodic fsck) rather than relying on ListApps.
//
// Returns an empty slice (not an error) when the apps dir does not yet
// exist, matching the InMemory backend's "fresh store has no apps" shape.
func (s *FSAppStore) ListApps() ([]*admin.AppRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.appsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*admin.AppRegistration{}, nil
		}
		return nil, err
	}

	out := make([]*admin.AppRegistration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var app admin.AppRegistration
		if err := json.Unmarshal(data, &app); err != nil {
			// Skip corrupt files — see godoc for rationale.
			continue
		}
		// Take address of a fresh copy; ranging by value re-uses the loop var.
		clone := app
		out = append(out, &clone)
	}
	return out, nil
}

// DeleteApp removes the registration for clientID. Returns admin.ErrAppNotFound
// if no such registration exists, matching InMemoryAppStore semantics.
func (s *FSAppStore) DeleteApp(clientID string) error {
	path, err := s.appPath(clientID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return admin.ErrAppNotFound
	}
	return os.Remove(path)
}
