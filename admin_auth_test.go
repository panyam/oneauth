package oneauth_test

import (
	"net/http/httptest"
	"testing"

	oa "github.com/panyam/oneauth"
)

func TestNoAuth_AllowsEverything(t *testing.T) {
	auth := oa.NewNoAuth()
	req := httptest.NewRequest("GET", "/admin/hosts", nil)
	if err := auth.Authenticate(req); err != nil {
		t.Errorf("NoAuth should allow all requests, got %v", err)
	}
}

func TestAPIKeyAuth_ValidKey(t *testing.T) {
	auth := oa.NewAPIKeyAuth("my-secret-key")
	req := httptest.NewRequest("GET", "/admin/hosts", nil)
	req.Header.Set("X-Admin-Key", "my-secret-key")
	if err := auth.Authenticate(req); err != nil {
		t.Errorf("Should accept valid key, got %v", err)
	}
}

func TestAPIKeyAuth_MissingKey(t *testing.T) {
	auth := oa.NewAPIKeyAuth("my-secret-key")
	req := httptest.NewRequest("GET", "/admin/hosts", nil)
	err := auth.Authenticate(req)
	if err != oa.ErrAdminUnauthorized {
		t.Errorf("Expected ErrAdminUnauthorized, got %v", err)
	}
}

func TestAPIKeyAuth_WrongKey(t *testing.T) {
	auth := oa.NewAPIKeyAuth("my-secret-key")
	req := httptest.NewRequest("GET", "/admin/hosts", nil)
	req.Header.Set("X-Admin-Key", "wrong-key")
	err := auth.Authenticate(req)
	if err != oa.ErrAdminForbidden {
		t.Errorf("Expected ErrAdminForbidden, got %v", err)
	}
}

func TestAPIKeyAuth_TimingAttack(t *testing.T) {
	auth := oa.NewAPIKeyAuth("correct-key-12345")
	req := httptest.NewRequest("GET", "/admin/hosts", nil)

	// Partial match should still fail
	req.Header.Set("X-Admin-Key", "correct-key-12346")
	if err := auth.Authenticate(req); err == nil {
		t.Error("Should reject nearly-matching key")
	}
}
