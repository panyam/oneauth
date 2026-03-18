package core

import (
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// User represents a unified user account
type User interface {
	Id() string
	Profile() map[string]any
}

// BasicUser is a simple implementation of the User interface
type BasicUser struct {
	ID          string
	ProfileData map[string]any
}

func (b *BasicUser) Id() string              { return b.ID }
func (b *BasicUser) Profile() map[string]any { return b.ProfileData }

// Identity represents a contact method (email, phone) that can be verified
type Identity struct {
	Type      string    `json:"type"`       // "email", "phone"
	Value     string    `json:"value"`      // "john@example.com", "+1-555-1234"
	UserID    string    `json:"user_id"`    // which user owns this identity
	Verified  bool      `json:"verified"`   // has any channel verified this identity?
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   int       `json:"version"` // optimistic locking version
}

// Channel represents an authentication mechanism/provider
type Channel struct {
	Provider    string         `json:"provider"`     // "local", "google", "github"
	IdentityKey string         `json:"identity_key"` // "email:john@example.com"
	Credentials map[string]any `json:"credentials"`  // password_hash, access_token, etc.
	Profile     map[string]any `json:"profile"`      // optional data from provider
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	ExpiresAt   time.Time      `json:"expires_at"` // when channel auth expires and needs re-auth
	Version     int            `json:"version"`    // optimistic locking version
}

// IsExpired returns true if the channel has an expiration time set and it has passed
func (c *Channel) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// IdentityKey creates a consistent identity key from type and value
func IdentityKey(identityType, identityValue string) string {
	return identityType + ":" + identityValue
}

// HandleUserFunc is called after successful authentication (OAuth or local).
type HandleUserFunc func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request)
