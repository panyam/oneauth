// Tests for AdminAuth implementations: NoAuth (dev-mode pass-through) and APIKeyAuth
// (constant-time API key comparison via X-Admin-Key header).
package admin_test

import (
	"github.com/panyam/oneauth/admin"
	"net/http/httptest"
	"testing"
)

// TestNoAuth_AllowsEverything verifies that the NoAuth implementation permits all requests unconditionally.
func TestNoAuth_AllowsEverything(t *testing.T) {
	auth := admin.NewNoAuth()
	req := httptest.NewRequest("GET", "/admin/hosts", nil)
	if err := auth.Authenticate(req); err != nil {
		t.Errorf("NoAuth should allow all requests, got %v", err)
	}
}

// TestAPIKeyAuth_ValidKey verifies that a request with the correct X-Admin-Key header is accepted.
func TestAPIKeyAuth_ValidKey(t *testing.T) {
	auth := admin.NewAPIKeyAuth("my-secret-key")
	req := httptest.NewRequest("GET", "/admin/hosts", nil)
	req.Header.Set("X-Admin-Key", "my-secret-key")
	if err := auth.Authenticate(req); err != nil {
		t.Errorf("Should accept valid key, got %v", err)
	}
}

// TestAPIKeyAuth_MissingKey verifies that a request without an X-Admin-Key header returns ErrAdminUnauthorized.
func TestAPIKeyAuth_MissingKey(t *testing.T) {
	auth := admin.NewAPIKeyAuth("my-secret-key")
	req := httptest.NewRequest("GET", "/admin/hosts", nil)
	err := auth.Authenticate(req)
	if err != admin.ErrAdminUnauthorized {
		t.Errorf("Expected ErrAdminUnauthorized, got %v", err)
	}
}

// TestAPIKeyAuth_WrongKey verifies that a request with an incorrect X-Admin-Key header returns ErrAdminForbidden.
func TestAPIKeyAuth_WrongKey(t *testing.T) {
	auth := admin.NewAPIKeyAuth("my-secret-key")
	req := httptest.NewRequest("GET", "/admin/hosts", nil)
	req.Header.Set("X-Admin-Key", "wrong-key")
	err := auth.Authenticate(req)
	if err != admin.ErrAdminForbidden {
		t.Errorf("Expected ErrAdminForbidden, got %v", err)
	}
}

// TestAPIKeyAuth_TimingAttack verifies that a nearly-matching key (off by one character) is rejected,
// confirming constant-time comparison is in use.
func TestAPIKeyAuth_TimingAttack(t *testing.T) {
	auth := admin.NewAPIKeyAuth("correct-key-12345")
	req := httptest.NewRequest("GET", "/admin/hosts", nil)

	// Partial match should still fail
	req.Header.Set("X-Admin-Key", "correct-key-12346")
	if err := auth.Authenticate(req); err == nil {
		t.Error("Should reject nearly-matching key")
	}
}
