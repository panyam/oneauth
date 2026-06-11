package admin_test

// OAuth 2.1 §3.1.2.1 / RFC 6749 §3.1.2.1 redirect-URI HTTPS enforcement
// with RFC 8252 §7.1 (private-use schemes) and §7.3 (loopback) carve-outs.
// See: docs/OAUTH21_ALIGNMENT.md row 6.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
)

func newRegistrarForRedirectTests(t *testing.T) *admin.AppRegistrar {
	t.Helper()
	return admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())
}

func registerWithRedirects(t *testing.T, r *admin.AppRegistrar, uris []string) error {
	t.Helper()
	_, err := r.Register(context.Background(), &admin.RegisterRequest{
		Metadata: &admin.DCRRequest{
			ClientName:   "test-app",
			RedirectURIs: uris,
		},
		IssuerBaseURL: "https://oneauth.example.com",
	})
	return err
}

func TestRedirectURI_AcceptsHTTPS(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"https://app.example/cb"})
	if err != nil {
		t.Errorf("https URI must be accepted; got %v", err)
	}
}

func TestRedirectURI_AcceptsHTTPLoopbackByName(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"http://localhost:53682/callback"})
	if err != nil {
		t.Errorf("http://localhost must be accepted per RFC 8252 §7.3; got %v", err)
	}
}

func TestRedirectURI_AcceptsHTTPLoopbackIPv4(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"http://127.0.0.1:8080/cb"})
	if err != nil {
		t.Errorf("http://127.0.0.1 must be accepted per RFC 8252 §7.3; got %v", err)
	}
}

func TestRedirectURI_AcceptsHTTPLoopbackIPv6(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"http://[::1]:8080/cb"})
	if err != nil {
		t.Errorf("http://[::1] must be accepted per RFC 8252 §7.3; got %v", err)
	}
}

func TestRedirectURI_AcceptsPrivateUseScheme(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"com.example.app:/oauth/callback"})
	if err != nil {
		t.Errorf("private-use reverse-DNS scheme must be accepted per RFC 8252 §7.1; got %v", err)
	}
}

func TestRedirectURI_RejectsHTTPNonLoopback(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"http://app.example/cb"})
	if !errors.Is(err, admin.ErrInvalidClientMetadata) {
		t.Errorf("http://non-loopback MUST be rejected per OAuth 2.1 §3.1.2.1; got %v", err)
	}
}

func TestRedirectURI_RejectsHTTPLoopbackLookalike(t *testing.T) {
	// "localhost.attacker.com" is NOT loopback; the substring check would
	// be a classic bypass. Ensure exact match.
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"http://localhost.attacker.com/cb"})
	if !errors.Is(err, admin.ErrInvalidClientMetadata) {
		t.Errorf("http://localhost.attacker.com MUST be rejected (substring bypass guard); got %v", err)
	}
}

func TestRedirectURI_RejectsFragment(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"https://app.example/cb#token=stolen"})
	if !errors.Is(err, admin.ErrInvalidClientMetadata) {
		t.Errorf("redirect_uri with fragment MUST be rejected per RFC 6749 §3.1.2; got %v", err)
	}
}

func TestRedirectURI_RejectsDataScheme(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"javascript:alert(1)"})
	if !errors.Is(err, admin.ErrInvalidClientMetadata) {
		t.Errorf("javascript: scheme MUST be rejected; got %v", err)
	}
}

func TestRedirectURI_RejectsRelativeURL(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{"/callback"})
	if !errors.Is(err, admin.ErrInvalidClientMetadata) {
		t.Errorf("relative redirect_uri MUST be rejected; got %v", err)
	}
}

func TestRedirectURI_RejectsEmpty(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{""})
	if !errors.Is(err, admin.ErrInvalidClientMetadata) {
		t.Errorf("empty redirect_uri MUST be rejected; got %v", err)
	}
}

func TestRedirectURI_RejectsAnyOneOfMultiple(t *testing.T) {
	// A single bad entry in the list must reject the whole registration.
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, []string{
		"https://app.example/cb1",
		"http://app.example/cb2", // bad
		"https://app.example/cb3",
	})
	if !errors.Is(err, admin.ErrInvalidClientMetadata) {
		t.Errorf("any single non-compliant URI MUST reject the whole list; got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "cb2") {
		t.Errorf("error must identify the offending URI; got %v", err)
	}
}

func TestRedirectURI_EmptyListAccepted(t *testing.T) {
	// DCR §2 permits clients that don't use redirect-based flows to omit
	// redirect_uris entirely (e.g., client_credentials-only clients).
	r := newRegistrarForRedirectTests(t)
	err := registerWithRedirects(t, r, nil)
	if err != nil {
		t.Errorf("empty redirect_uris list must be accepted; got %v", err)
	}
}

func TestRedirectURI_UpdateAppliesSameValidation(t *testing.T) {
	r := newRegistrarForRedirectTests(t)
	resp, err := r.Register(context.Background(), &admin.RegisterRequest{
		Metadata: &admin.DCRRequest{
			ClientName:   "test-app",
			RedirectURIs: []string{"https://app.example/cb"},
		},
		IssuerBaseURL: "https://oneauth.example.com",
	})
	if err != nil {
		t.Fatalf("initial register failed: %v", err)
	}

	_, err = r.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{
		ClientID:    resp.Registration.ClientID,
		AccessToken: resp.Registration.RegistrationAccessToken,
		Metadata: &admin.DCRRequest{
			ClientName:   "test-app",
			RedirectURIs: []string{"http://app.example/cb"}, // bad
		},
	})
	if !errors.Is(err, admin.ErrInvalidClientMetadata) {
		t.Errorf("UpdateRegistration MUST apply the same redirect-URI validation; got %v", err)
	}
}
