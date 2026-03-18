package admin

import (
	"crypto/subtle"
	"fmt"
	"net/http"
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
