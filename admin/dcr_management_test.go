package admin_test

// Tests for the RFC 7592 Dynamic Client Registration Management protocol —
// both the transport-agnostic ClientRegistrationManager interface and the
// HTTP wrapper DCRManagementHandler that exposes it at /apps/dcr/{client_id}.
//
// References:
//   - RFC 7592 (https://www.rfc-editor.org/rfc/rfc7592):
//     "OAuth 2.0 Dynamic Client Registration Management Protocol"
//   - See: https://github.com/panyam/oneauth/issues/168
//   - Blueprint for transport-agnostic admin/ refactor: issue 172.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerDCRClient is a test helper: drives a DCR registration through the
// HTTP handler and returns the raw response map (so tests can assert on
// whichever fields they care about).
func registerDCRClient(t *testing.T, registrar *admin.AppRegistrar, body string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "auth.example.com"
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

// --- Interface-level tests (exercise ClientRegistrationManager directly) ---

// TestGetRegistration_ValidTokenReturnsResponse verifies the happy-path: a
// caller holding the registration_access_token issued at registration time
// can fetch the registration as RFC 7591/7592 JSON.
func TestGetRegistration_ValidTokenReturnsResponse(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar,
		`{"client_name":"Read Me","redirect_uris":["https://app.example/cb"]}`)

	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	resp, err := registrar.GetRegistration(clientID, token)
	require.NoError(t, err)
	assert.Equal(t, clientID, resp.ClientID)
	assert.Equal(t, "Read Me", resp.ClientName)
	assert.Equal(t, []string{"https://app.example/cb"}, resp.RedirectURIs)
	assert.Equal(t, token, resp.RegistrationAccessToken)
	assert.Empty(t, resp.ClientSecret, "client_secret must NOT be echoed on read")
}

// TestGetRegistration_WrongTokenReturnsUnauthorized verifies that a caller
// presenting a token that does not match the stored registration_access_token
// is rejected with ErrUnauthorized — even though the client_id exists.
func TestGetRegistration_WrongTokenReturnsUnauthorized(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Wrong Token"}`)

	_, err := registrar.GetRegistration(registered["client_id"].(string), "definitely-not-the-token")
	assert.True(t, errors.Is(err, admin.ErrUnauthorized), "expected ErrUnauthorized, got %v", err)
}

// TestGetRegistration_UnknownClientReturnsUnauthorized verifies that asking
// for a client_id that doesn't exist returns ErrUnauthorized — NOT a "not
// found" error. Distinguishing them would let the management endpoint be
// used to enumerate valid client_ids.
func TestGetRegistration_UnknownClientReturnsUnauthorized(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	_, err := registrar.GetRegistration("app_does_not_exist", "any-token")
	assert.True(t, errors.Is(err, admin.ErrUnauthorized), "expected ErrUnauthorized, got %v", err)
}

// TestGetRegistration_LegacyRegistrationCannotBeRead verifies that apps
// registered via the non-DCR endpoint (/apps/register), which do NOT receive
// a registration_access_token, are not readable through the management
// interface. Only DCR-registered clients participate in RFC 7592.
func TestGetRegistration_LegacyRegistrationCannotBeRead(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	// Register through the legacy endpoint — no management token issued.
	body := `{"client_domain":"legacy.example","signing_alg":"HS256"}`
	req := httptest.NewRequest(http.MethodPost, "/apps/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)
	var legacy map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &legacy))

	_, err := registrar.GetRegistration(legacy["client_id"].(string), "any-token")
	assert.True(t, errors.Is(err, admin.ErrUnauthorized), "legacy app must not be readable via mgmt endpoint")
}

// TestGetRegistration_EmptyInputsReturnUnauthorized covers the boundary cases
// — empty client_id, empty token — to ensure they short-circuit to
// ErrUnauthorized rather than reaching the store.
func TestGetRegistration_EmptyInputsReturnUnauthorized(t *testing.T) {
	registrar := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())

	for _, tc := range []struct {
		name              string
		clientID, token   string
	}{
		{"empty clientID", "", "some-token"},
		{"empty token", "app_x", ""},
		{"both empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registrar.GetRegistration(tc.clientID, tc.token)
			assert.True(t, errors.Is(err, admin.ErrUnauthorized), "expected ErrUnauthorized for %s", tc.name)
		})
	}
}

// --- HTTP-layer tests (exercise DCRManagementHandler) ---

// TestDCRManagement_GET_HappyPath verifies the wire-level GET behavior: status
// 200, JSON body that matches the registered client, and the no-store cache
// headers required for token-bearing endpoints.
func TestDCRManagement_GET_HappyPath(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar,
		`{"client_name":"GET Test","redirect_uris":["https://app.example/cb"]}`)

	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	req := httptest.NewRequest(http.MethodGet, "/apps/dcr/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, clientID, got["client_id"])
	assert.Equal(t, "GET Test", got["client_name"])
	_, hasSecret := got["client_secret"]
	assert.False(t, hasSecret, "GET response must NOT include client_secret")
}

// TestDCRManagement_GET_WrongToken returns 401 + WWW-Authenticate when the
// Bearer value does not match the stored registration_access_token.
func TestDCRManagement_GET_WrongToken(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Wrong Token HTTP"}`)

	req := httptest.NewRequest(http.MethodGet, "/apps/dcr/"+registered["client_id"].(string), nil)
	req.Header.Set("Authorization", "Bearer not-the-real-token")
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "Bearer")
}

// TestDCRManagement_GET_MissingAuthHeader returns 401 with no auth header at all.
func TestDCRManagement_GET_MissingAuthHeader(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"No Auth Header"}`)

	req := httptest.NewRequest(http.MethodGet, "/apps/dcr/"+registered["client_id"].(string), nil)
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestDCRManagement_GET_UnknownClient_Returns401NotFound verifies the
// information-disclosure guard: an unknown client_id must look identical to a
// wrong-token response. 401, not 404.
func TestDCRManagement_GET_UnknownClient_Returns401NotFound(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	req := httptest.NewRequest(http.MethodGet, "/apps/dcr/app_phantom", nil)
	req.Header.Set("Authorization", "Bearer something")
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "must not reveal that the client_id does not exist")
	assert.NotEqual(t, http.StatusNotFound, rr.Code)
}

// TestDCRManagement_NonGETMethodReturns405 verifies that PUT / DELETE / POST
// against /apps/dcr/{client_id} return 405 with an Allow: GET header until
// #169 / #170 land.
func TestDCRManagement_NonGETMethodReturns405(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"405 Test"}`)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/apps/dcr/"+registered["client_id"].(string), nil)
			req.Header.Set("Authorization", "Bearer "+registered["registration_access_token"].(string))
			rr := httptest.NewRecorder()
			registrar.Handler().ServeHTTP(rr, req)

			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
			assert.Equal(t, "GET", rr.Header().Get("Allow"))
		})
	}
}

// TestDCRManagement_GET_DoesNotShadowDCRRegister verifies the routing
// precedence: POST /apps/dcr (no trailing slash) still hits the RFC 7591
// registration handler, even after we mount the /apps/dcr/ prefix for
// management. Regression guard for go ServeMux longest-prefix-match behavior.
func TestDCRManagement_GET_DoesNotShadowDCRRegister(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	body := `{"client_name":"Routing Guard"}`
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code, "POST /apps/dcr must still register; got %s", rr.Body.String())
}
