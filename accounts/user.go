// Package accounts owns the federated end-user account model — the data
// shape shared by both username/password (localauth) and provider-mediated
// (federatedauth) authentication flows.
//
// What this package owns:
//   - User / BasicUser — the account principal as seen by the application
//   - Identity         — a verifiable contact (email, phone) owned by one User
//   - Channel          — per-provider credentials (local, google, github, …)
//   - UserStore, IdentityStore, ChannelStore, UsernameStore — store interfaces
//   - AuthError        — structured account-level errors used by both flows
//
// What this package deliberately does NOT own:
//   - OAuth access/refresh tokens, API keys, scopes — see core/
//   - Username/password specifics (signup policy, credentials shape) — see localauth/
//   - OAuth/SAML callback orchestration — see federatedauth/
package accounts

import (
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// User represents a unified user account.
type User interface {
	Id() string
	Profile() map[string]any
}

// BasicUser is a simple implementation of the User interface.
type BasicUser struct {
	ID          string
	ProfileData map[string]any
}

func (b *BasicUser) Id() string              { return b.ID }
func (b *BasicUser) Profile() map[string]any { return b.ProfileData }

// Identity represents a contact method (email, phone) that can be verified.
type Identity struct {
	Type      string    `json:"type"`       // "email", "phone"
	Value     string    `json:"value"`      // "john@example.com", "+1-555-1234"
	UserID    string    `json:"user_id"`    // which user owns this identity
	Verified  bool      `json:"verified"`   // has any channel verified this identity?
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   int       `json:"version"` // optimistic locking version
}

// Channel represents an authentication mechanism/provider tied to an Identity.
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

// IsExpired returns true if the channel has an expiration time set and it has passed.
func (c *Channel) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// IdentityKey creates a consistent identity key from type and value.
func IdentityKey(identityType, identityValue string) string {
	return identityType + ":" + identityValue
}

// HandleUserFunc is called after successful authentication (OAuth or local)
// to let the host application complete its session/redirect logic.
type HandleUserFunc func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request)

// DetectUsernameType attempts to detect what type of username was provided.
// Returns "email" if it contains "@", "phone" if it starts with + or a digit,
// otherwise "username". Used by both localauth's password validator and
// apiauth's password grant when the host doesn't supply an explicit type.
func DetectUsernameType(username string) string {
	if len(username) == 0 {
		return "username"
	}
	for _, c := range username {
		if c == '@' {
			return "email"
		}
	}
	c := username[0]
	if c == '+' || (c >= '0' && c <= '9') {
		return "phone"
	}
	return "username"
}

// LinkedChannels extracts the channels list from a user profile.
//
// The list is stored under profile["channels"] as either []string or []any
// (depending on how it was deserialized). Returns an empty slice if the
// profile is nil or the channels key is missing/of the wrong type.
func LinkedChannels(profile map[string]any) []string {
	if profile == nil {
		return []string{}
	}
	switch v := profile["channels"].(type) {
	case []string:
		return v
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return []string{}
	}
}
