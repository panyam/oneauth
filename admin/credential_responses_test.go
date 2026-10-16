package admin_test

// Responses that carry a client secret or a registration access token must
// not be cached (RFC 6749 §5.1, which RFC 7591 §3.2.1 points to), the admin
// listing has no business returning every client's RFC 7592 management
// token, and registration_client_uri must not come from a request's Host
// header.
//
// References:
//   - RFC 6749 §5.1 (https://www.rfc-editor.org/rfc/rfc6749#section-5.1)
//   - RFC 7591 §3.2.1 (https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1)
//   - RFC 7592 §3 (https://www.rfc-editor.org/rfc/rfc7592#section-3)
//   - CWE-525 (https://cwe.mitre.org/data/definitions/525.html), CWE-644 (https://cwe.mitre.org/data/definitions/644.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
)

const testAdminKey = "admin-key-for-tests"

func newCredentialRegistrar(t *testing.T) http.Handler {
	t.Helper()
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewAPIKeyAuth(testAdminKey))
	return r.Handler()
}

func serveAdmin(h http.Handler, method, target, body string, admin bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	if admin {
		req.Header.Set("X-Admin-Key", testAdminKey)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func dcrBody() string {
	return `{"client_name":"c","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_basic"}`
}

func assertNoStore(t *testing.T, rr *httptest.ResponseRecorder, what string) {
	t.Helper()
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"), "%s must not be cacheable", what)
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"), what)
}

func register(t *testing.T, h http.Handler) map[string]any {
	t.Helper()
	rr := serveAdmin(h, http.MethodPost, "/apps/dcr", dcrBody(), true)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	return body
}

func TestCredentialResponses_DCRRegistrationIsNoStore(t *testing.T) {
	h := newCredentialRegistrar(t)
	rr := serveAdmin(h, http.MethodPost, "/apps/dcr", dcrBody(), true)
	require.Equal(t, http.StatusCreated, rr.Code)
	assertNoStore(t, rr, "a DCR response with client_secret")

	bad := serveAdmin(h, http.MethodPost, "/apps/dcr", `{`, true)
	assertNoStore(t, bad, "a DCR error")
}

func TestCredentialResponses_AdminEndpointsAreNoStore(t *testing.T) {
	h := newCredentialRegistrar(t)
	id := register(t, h)["client_id"].(string)

	assertNoStore(t, serveAdmin(h, http.MethodGet, "/apps", "", true), "the admin app list")
	assertNoStore(t, serveAdmin(h, http.MethodGet, "/apps/"+id, "", true), "an admin app read")
	rot := serveAdmin(h, http.MethodPost, "/apps/"+id+"/rotate", `{}`, true)
	require.Equal(t, http.StatusOK, rot.Code, rot.Body.String())
	assert.Contains(t, rot.Body.String(), "client_secret")
	assertNoStore(t, rot, "a rotated client_secret")
	assertNoStore(t, serveAdmin(h, http.MethodGet, "/apps", "", false), "an admin error")
}

// The admin view lists apps; the management token belongs to each client and
// is returned only by the RFC 7591 / 7592 endpoints.
func TestCredentialResponses_AdminViewOmitsRegistrationAccessToken(t *testing.T) {
	h := newCredentialRegistrar(t)
	reg := register(t, h)
	token := reg["registration_access_token"].(string)
	require.NotEmpty(t, token)
	id := reg["client_id"].(string)

	for _, target := range []string{"/apps", "/apps/" + id} {
		rr := serveAdmin(h, http.MethodGet, target, "", true)
		require.Equal(t, http.StatusOK, rr.Code)
		assert.NotContains(t, rr.Body.String(), token, target)
		assert.NotContains(t, rr.Body.String(), "registration_access_token", target)
	}

	// The client's own RFC 7592 read still returns it.
	req := httptest.NewRequest(http.MethodGet, "/apps/dcr/"+id, nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "registration_access_token")
}

// See: https://cwe.mitre.org/data/definitions/644.html
func TestCredentialResponses_RegistrationURIIgnoresForeignHost(t *testing.T) {
	t.Run("configured base URL wins over Host", func(t *testing.T) {
		r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewAPIKeyAuth(testAdminKey))
		r.IssuerBaseURL = "https://as.example.com"
		req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(dcrBody()))
		req.Host = "evil.example"
		req.Header.Set("X-Admin-Key", testAdminKey)
		rr := httptest.NewRecorder()
		r.Handler().ServeHTTP(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
		assert.Contains(t, rr.Body.String(), `"registration_client_uri":"https://as.example.com/apps/dcr/`)
		assert.NotContains(t, rr.Body.String(), "evil.example")
	})
	t.Run("unconfigured, a non-loopback Host is refused", func(t *testing.T) {
		h := newCredentialRegistrar(t)
		req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(dcrBody()))
		req.Host = "evil.example"
		req.Header.Set("X-Admin-Key", testAdminKey)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.NotContains(t, rr.Body.String(), "evil.example")
	})
	t.Run("unconfigured, loopback is derived for local development", func(t *testing.T) {
		reg := register(t, newCredentialRegistrar(t))
		assert.True(t, strings.HasPrefix(reg["registration_client_uri"].(string), "http://127.0.0.1:8080/apps/dcr/"))
	})
}
