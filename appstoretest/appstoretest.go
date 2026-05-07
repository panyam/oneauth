// Package appstoretest provides a shared contract test suite for all
// AppRegistrationStore implementations. Each backend (inmem, fs, gorm)
// calls these tests with its own factory function. Mirrors keystoretest.
package appstoretest

import (
	"sort"
	"testing"
	"time"

	"github.com/panyam/oneauth/admin"
)

// Factory creates a fresh AppRegistrationStore for each test.
type Factory func(t *testing.T) admin.AppRegistrationStore

// RunAll runs the complete AppRegistrationStore test suite against the provided factory.
func RunAll(t *testing.T, factory Factory) {
	t.Run("SaveAndGet", func(t *testing.T) { TestSaveAndGet(t, factory) })
	t.Run("NotFound", func(t *testing.T) { TestNotFound(t, factory) })
	t.Run("DeleteApp", func(t *testing.T) { TestDeleteApp(t, factory) })
	t.Run("DeleteNonexistent", func(t *testing.T) { TestDeleteNonexistent(t, factory) })
	t.Run("OverwriteApp", func(t *testing.T) { TestOverwriteApp(t, factory) })
	t.Run("ListApps", func(t *testing.T) { TestListApps(t, factory) })
	t.Run("ListAppsEmpty", func(t *testing.T) { TestListAppsEmpty(t, factory) })
	t.Run("Persistence", func(t *testing.T) { TestPersistence(t, factory) })
	t.Run("AllFieldsRoundTrip", func(t *testing.T) { TestAllFieldsRoundTrip(t, factory) })
}

// TestSaveAndGet verifies that SaveApp followed by GetApp returns the saved registration.
func TestSaveAndGet(t *testing.T, factory Factory) {
	s := factory(t)

	app := &admin.AppRegistration{
		ClientID:     "app_abc",
		ClientDomain: "example.com",
		SigningAlg:   "HS256",
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
	}

	if err := s.SaveApp(app); err != nil {
		t.Fatalf("SaveApp failed: %v", err)
	}

	got, err := s.GetApp("app_abc")
	if err != nil {
		t.Fatalf("GetApp failed: %v", err)
	}
	if got.ClientID != "app_abc" {
		t.Errorf("ClientID=%q, want app_abc", got.ClientID)
	}
	if got.ClientDomain != "example.com" {
		t.Errorf("ClientDomain=%q, want example.com", got.ClientDomain)
	}
	if got.SigningAlg != "HS256" {
		t.Errorf("SigningAlg=%q, want HS256", got.SigningAlg)
	}
}

// TestNotFound verifies that GetApp on a missing client_id returns ErrAppNotFound.
func TestNotFound(t *testing.T, factory Factory) {
	s := factory(t)

	_, err := s.GetApp("does-not-exist")
	if err != admin.ErrAppNotFound {
		t.Errorf("expected ErrAppNotFound, got %v", err)
	}
}

// TestDeleteApp verifies that DeleteApp removes the registration and subsequent
// GetApp returns ErrAppNotFound.
func TestDeleteApp(t *testing.T, factory Factory) {
	s := factory(t)

	app := &admin.AppRegistration{ClientID: "app_del", SigningAlg: "HS256", CreatedAt: time.Now()}
	if err := s.SaveApp(app); err != nil {
		t.Fatalf("SaveApp failed: %v", err)
	}

	if err := s.DeleteApp("app_del"); err != nil {
		t.Fatalf("DeleteApp failed: %v", err)
	}

	if _, err := s.GetApp("app_del"); err != admin.ErrAppNotFound {
		t.Errorf("expected ErrAppNotFound after delete, got %v", err)
	}
}

// TestDeleteNonexistent verifies that deleting a missing client_id returns ErrAppNotFound,
// matching KeyStorage.DeleteKey semantics.
func TestDeleteNonexistent(t *testing.T, factory Factory) {
	s := factory(t)

	err := s.DeleteApp("never-existed")
	if err != admin.ErrAppNotFound {
		t.Errorf("expected ErrAppNotFound, got %v", err)
	}
}

// TestOverwriteApp verifies that SaveApp on an existing client_id replaces the
// stored registration with the new metadata.
func TestOverwriteApp(t *testing.T, factory Factory) {
	s := factory(t)

	original := &admin.AppRegistration{ClientID: "app_ow", ClientDomain: "old.example", SigningAlg: "HS256", CreatedAt: time.Now()}
	updated := &admin.AppRegistration{ClientID: "app_ow", ClientDomain: "new.example", SigningAlg: "RS256", CreatedAt: time.Now()}

	if err := s.SaveApp(original); err != nil {
		t.Fatalf("SaveApp original failed: %v", err)
	}
	if err := s.SaveApp(updated); err != nil {
		t.Fatalf("SaveApp updated failed: %v", err)
	}

	got, err := s.GetApp("app_ow")
	if err != nil {
		t.Fatalf("GetApp failed: %v", err)
	}
	if got.ClientDomain != "new.example" {
		t.Errorf("ClientDomain=%q, want new.example (overwrite)", got.ClientDomain)
	}
	if got.SigningAlg != "RS256" {
		t.Errorf("SigningAlg=%q, want RS256 (overwrite)", got.SigningAlg)
	}
}

// TestListApps verifies that ListApps returns every saved registration.
func TestListApps(t *testing.T, factory Factory) {
	s := factory(t)

	for _, id := range []string{"app_alpha", "app_beta", "app_gamma"} {
		if err := s.SaveApp(&admin.AppRegistration{ClientID: id, SigningAlg: "HS256", CreatedAt: time.Now()}); err != nil {
			t.Fatalf("SaveApp %s failed: %v", id, err)
		}
	}

	apps, err := s.ListApps()
	if err != nil {
		t.Fatalf("ListApps failed: %v", err)
	}
	if len(apps) != 3 {
		t.Fatalf("expected 3 apps, got %d", len(apps))
	}

	gotIDs := make([]string, 0, len(apps))
	for _, a := range apps {
		gotIDs = append(gotIDs, a.ClientID)
	}
	sort.Strings(gotIDs)
	want := []string{"app_alpha", "app_beta", "app_gamma"}
	for i, id := range want {
		if gotIDs[i] != id {
			t.Errorf("apps[%d]=%s, want %s", i, gotIDs[i], id)
		}
	}
}

// TestListAppsEmpty verifies that ListApps on a fresh store returns an empty slice
// (not an error).
func TestListAppsEmpty(t *testing.T, factory Factory) {
	s := factory(t)

	apps, err := s.ListApps()
	if err != nil {
		t.Fatalf("ListApps failed: %v", err)
	}
	if len(apps) != 0 {
		t.Errorf("expected 0 apps, got %d", len(apps))
	}
}

// TestPersistence verifies that a saved registration is visible to subsequent reads
// from the same store handle. For persistent backends (FS, GORM) this catches
// write-buffering bugs; for InMem it is trivially true.
func TestPersistence(t *testing.T, factory Factory) {
	s := factory(t)

	app := &admin.AppRegistration{ClientID: "app_persist", ClientDomain: "p.example", SigningAlg: "HS256", CreatedAt: time.Now()}
	if err := s.SaveApp(app); err != nil {
		t.Fatalf("SaveApp failed: %v", err)
	}

	got, err := s.GetApp("app_persist")
	if err != nil {
		t.Fatalf("GetApp after save failed: %v", err)
	}
	if got.ClientDomain != "p.example" {
		t.Errorf("ClientDomain=%q, want p.example", got.ClientDomain)
	}
}

// TestAllFieldsRoundTrip verifies that every field on AppRegistration survives a
// SaveApp/GetApp round-trip. Catches backend serialization bugs (e.g., GORM
// forgetting to JSON-encode slice fields).
func TestAllFieldsRoundTrip(t *testing.T, factory Factory) {
	s := factory(t)

	created := time.Now().UTC().Truncate(time.Second)
	app := &admin.AppRegistration{
		ClientID:                  "app_full",
		ClientDomain:              "full.example",
		SigningAlg:                "RS256",
		MaxRooms:                  42,
		MaxMsgRate:                3.14,
		AuthorizationDetailsTypes: []string{"payment_initiation", "account_information"},
		CreatedAt:                 created,
		Revoked:                   false,
		ClientName:                "Full App",
		ClientURI:                 "https://full.example",
		RedirectURIs:              []string{"https://full.example/cb", "http://localhost/cb"},
		GrantTypes:                []string{"authorization_code", "refresh_token"},
		Scope:                     "read write",
		TokenEndpointAuthMethod:   "private_key_jwt",
		RegistrationAccessToken:   "reg-tok-abc",
		RegistrationClientURI:     "https://issuer.example/apps/dcr/app_full",
	}

	if err := s.SaveApp(app); err != nil {
		t.Fatalf("SaveApp failed: %v", err)
	}

	got, err := s.GetApp("app_full")
	if err != nil {
		t.Fatalf("GetApp failed: %v", err)
	}

	if got.ClientName != "Full App" {
		t.Errorf("ClientName=%q, want %q", got.ClientName, "Full App")
	}
	if got.ClientURI != "https://full.example" {
		t.Errorf("ClientURI=%q", got.ClientURI)
	}
	if len(got.RedirectURIs) != 2 || got.RedirectURIs[0] != "https://full.example/cb" {
		t.Errorf("RedirectURIs=%v", got.RedirectURIs)
	}
	if len(got.GrantTypes) != 2 || got.GrantTypes[0] != "authorization_code" {
		t.Errorf("GrantTypes=%v", got.GrantTypes)
	}
	if got.Scope != "read write" {
		t.Errorf("Scope=%q", got.Scope)
	}
	if got.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Errorf("TokenEndpointAuthMethod=%q", got.TokenEndpointAuthMethod)
	}
	if got.RegistrationAccessToken != "reg-tok-abc" {
		t.Errorf("RegistrationAccessToken=%q", got.RegistrationAccessToken)
	}
	if got.RegistrationClientURI != "https://issuer.example/apps/dcr/app_full" {
		t.Errorf("RegistrationClientURI=%q", got.RegistrationClientURI)
	}
	if len(got.AuthorizationDetailsTypes) != 2 || got.AuthorizationDetailsTypes[0] != "payment_initiation" {
		t.Errorf("AuthorizationDetailsTypes=%v", got.AuthorizationDetailsTypes)
	}
	if got.MaxRooms != 42 {
		t.Errorf("MaxRooms=%d", got.MaxRooms)
	}
	if got.MaxMsgRate != 3.14 {
		t.Errorf("MaxMsgRate=%f", got.MaxMsgRate)
	}
}
