// Package fs provides a file system-based credential store for oneauth client.
package fs

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/panyam/oneauth/client"
)

// FSCredentialStore stores credentials as a JSON file on the filesystem
type FSCredentialStore struct {
	mu       sync.RWMutex
	path     string
	servers  map[string]*client.ServerCredential
	modified bool
}

// credentialFile is the JSON structure stored on disk
type credentialFile struct {
	Servers map[string]*client.ServerCredential `json:"servers"`
}

// NewFSCredentialStore creates a new FS-based credential store.
// If path is empty, defaults to ~/.config/<appName>/credentials.json
func NewFSCredentialStore(path string, appName string) (*FSCredentialStore, error) {
	if path == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("could not determine config directory: %w", err)
			}
			configDir = filepath.Join(home, ".config")
		}
		if appName == "" {
			appName = "oneauth"
		}
		path = filepath.Join(configDir, appName, "credentials.json")
	}

	store := &FSCredentialStore{
		path:    path,
		servers: make(map[string]*client.ServerCredential),
	}

	// Load existing credentials if file exists
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

// load reads credentials from disk
func (s *FSCredentialStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	var file credentialFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("failed to parse credentials file: %w", err)
	}

	s.servers = file.Servers
	if s.servers == nil {
		s.servers = make(map[string]*client.ServerCredential)
	}

	return nil
}

// normalizeURL normalizes a server URL for use as a key
func normalizeURL(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	if u.Scheme == "" {
		u.Scheme = "https"
	}

	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}

// GetCredential retrieves a credential for a server URL
func (s *FSCredentialStore) GetCredential(serverURL string) (*client.ServerCredential, error) {
	key, err := normalizeURL(serverURL)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, ok := s.servers[key]
	if !ok {
		return nil, nil
	}

	return cred, nil
}

// SetCredential stores a credential for a server URL
func (s *FSCredentialStore) SetCredential(serverURL string, cred *client.ServerCredential) error {
	key, err := normalizeURL(serverURL)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.servers[key] = cred
	s.modified = true

	return nil
}

// RemoveCredential removes a credential for a server URL
func (s *FSCredentialStore) RemoveCredential(serverURL string) error {
	key, err := normalizeURL(serverURL)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.servers, key)
	s.modified = true

	return nil
}

// ListServers returns all server URLs with stored credentials
func (s *FSCredentialStore) ListServers() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	servers := make([]string, 0, len(s.servers))
	for k := range s.servers {
		servers = append(servers, k)
	}

	return servers, nil
}

// Save persists credentials to disk
func (s *FSCredentialStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.modified {
		return nil
	}

	// Ensure directory exists with restricted permissions
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	file := credentialFile{Servers: s.servers}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize credentials: %w", err)
	}

	// Write with restricted permissions (owner read/write only)
	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	s.modified = false
	return nil
}

// Path returns the path to the credentials file
func (s *FSCredentialStore) Path() string {
	return s.path
}
