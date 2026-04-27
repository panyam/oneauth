// Package client provides client-side authentication utilities for oneauth.
// It includes credential storage, automatic token refresh, and HTTP client helpers.
package client

import (
	"time"

	"github.com/panyam/oneauth/core"
)

// ServerCredential holds authentication info for a single server
type ServerCredential struct {
	AccessToken          string                     `json:"access_token"`
	RefreshToken         string                     `json:"refresh_token,omitempty"`
	TokenType            string                     `json:"token_type,omitempty"`
	UserID               string                     `json:"user_id,omitempty"`
	UserEmail            string                     `json:"user_email,omitempty"`
	Scope                string                     `json:"scope,omitempty"`
	AuthorizationDetails []core.AuthorizationDetail `json:"authorization_details,omitempty"` // RFC 9396
	ExpiresAt            time.Time                  `json:"expires_at"`
	CreatedAt            time.Time                  `json:"created_at"`
}

// IsExpired returns true if the access token has expired
func (c *ServerCredential) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsExpiringSoon returns true if the token expires within the given duration
func (c *ServerCredential) IsExpiringSoon(within time.Duration) bool {
	return time.Now().Add(within).After(c.ExpiresAt)
}

// HasRefreshToken returns true if a refresh token is available
func (c *ServerCredential) HasRefreshToken() bool {
	return c.RefreshToken != ""
}

// CredentialStore defines the interface for storing and retrieving credentials
type CredentialStore interface {
	// GetCredential retrieves a credential for a server URL
	// Returns nil, nil if no credential exists for the server
	GetCredential(serverURL string) (*ServerCredential, error)

	// SetCredential stores a credential for a server URL
	SetCredential(serverURL string, cred *ServerCredential) error

	// RemoveCredential removes a credential for a server URL
	RemoveCredential(serverURL string) error

	// ListServers returns all server URLs with stored credentials
	ListServers() ([]string, error)

	// Save persists any pending changes (for stores that batch writes)
	Save() error
}

// noopCredentialStore is a CredentialStore that silently discards writes
// and returns "no credential" on reads. Used when NewAuthClient is called
// with a nil store — the client works for single-request flows (e.g.,
// LoginWithBrowser returning the credential directly) without persisting
// tokens between calls.
type noopCredentialStore struct{}

func (noopCredentialStore) GetCredential(string) (*ServerCredential, error) { return nil, nil }
func (noopCredentialStore) SetCredential(string, *ServerCredential) error   { return nil }
func (noopCredentialStore) RemoveCredential(string) error                   { return nil }
func (noopCredentialStore) ListServers() ([]string, error)                  { return nil, nil }
func (noopCredentialStore) Save() error                                     { return nil }
