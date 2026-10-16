package admin

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

// AdminAuth authenticates admin requests to protected endpoints
// (e.g., Host registration, key rotation).
type AdminAuth interface {
	// Authenticate checks whether the request is authorized.
	// Returns nil if authorized, or an error describing why not.
	Authenticate(r *http.Request) error
}

// Common errors for admin auth
var (
	ErrAdminUnauthorized = fmt.Errorf("admin authentication required")
	ErrAdminForbidden    = fmt.Errorf("admin access denied")
)

// NoAuth allows all requests. For development/testing only.
type NoAuth struct{}

func NewNoAuth() *NoAuth { return &NoAuth{} }

func (a *NoAuth) Authenticate(r *http.Request) error { return nil }

// APIKeyAuth authenticates requests using a shared API key
// passed in the X-Admin-Key header.
type APIKeyAuth struct {
	key string
}

// NewAPIKeyAuth creates an AdminAuth that validates the X-Admin-Key header.
func NewAPIKeyAuth(key string) *APIKeyAuth {
	return &APIKeyAuth{key: key}
}

func (a *APIKeyAuth) Authenticate(r *http.Request) error {
	provided := r.Header.Get("X-Admin-Key")
	if provided == "" {
		return ErrAdminUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(provided), []byte(a.key)) != 1 {
		return ErrAdminForbidden
	}
	return nil
}

// InitialAccessTokenAuth authenticates RFC 7591 §3 initial access tokens,
// sent as "Authorization: Bearer <token>". It lets an AS open dynamic client
// registration to clients that hold a registration token (MCP clients, say)
// without giving them the admin credential. Set it as
// AppRegistrar.RegistrationAuth; it is not an admin credential and opens no
// other route.
//
// Tokens are compared in constant time. Empty tokens are ignored, and with
// none configured every request is refused (ErrAdminUnauthorized).
type InitialAccessTokenAuth struct {
	tokens [][]byte
}

// NewInitialAccessTokenAuth accepts any of tokens. Rotate by listing the
// new token alongside the old until clients have moved over.
func NewInitialAccessTokenAuth(tokens ...string) *InitialAccessTokenAuth {
	a := &InitialAccessTokenAuth{}
	for _, t := range tokens {
		if t != "" {
			a.tokens = append(a.tokens, []byte(t))
		}
	}
	return a
}

// Authenticate returns ErrAdminUnauthorized when no bearer token is sent or
// none is configured, and ErrAdminForbidden for a token that matches none.
func (a *InitialAccessTokenAuth) Authenticate(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(a.tokens) == 0 || len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ErrAdminUnauthorized
	}
	presented := []byte(strings.TrimSpace(auth[len(prefix):]))
	ok := 0
	for _, t := range a.tokens {
		ok |= subtle.ConstantTimeCompare(presented, t)
	}
	if ok != 1 {
		return ErrAdminForbidden
	}
	return nil
}
