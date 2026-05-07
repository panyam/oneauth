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
	"context"
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

	resp, err := registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
		ClientID:    clientID,
		AccessToken: token,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Registration)
	got := resp.Registration
	assert.Equal(t, clientID, got.ClientID)
	assert.Equal(t, "Read Me", got.ClientName)
	assert.Equal(t, []string{"https://app.example/cb"}, got.RedirectURIs)
	assert.Equal(t, token, got.RegistrationAccessToken)
	assert.Empty(t, got.ClientSecret, "client_secret must NOT be echoed on read")
}

// TestGetRegistration_WrongTokenReturnsUnauthorized verifies that a caller
// presenting a token that does not match the stored registration_access_token
// is rejected with ErrUnauthorized — even though the client_id exists.
func TestGetRegistration_WrongTokenReturnsUnauthorized(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Wrong Token"}`)

	_, err := registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
		ClientID:    registered["client_id"].(string),
		AccessToken: "definitely-not-the-token",
	})
	assert.True(t, errors.Is(err, admin.ErrUnauthorized), "expected ErrUnauthorized, got %v", err)
}

// TestGetRegistration_UnknownClientReturnsUnauthorized verifies that asking
// for a client_id that doesn't exist returns ErrUnauthorized — NOT a "not
// found" error. Distinguishing them would let the management endpoint be
// used to enumerate valid client_ids.
func TestGetRegistration_UnknownClientReturnsUnauthorized(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	_, err := registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
		ClientID:    "app_does_not_exist",
		AccessToken: "any-token",
	})
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

	_, err := registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
		ClientID:    legacy["client_id"].(string),
		AccessToken: "any-token",
	})
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
			_, err := registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
				ClientID:    tc.clientID,
				AccessToken: tc.token,
			})
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

// TestDCRManagement_UnsupportedMethodReturns405 verifies that arbitrary verbs
// (POST, PATCH, etc.) return 405 with an Allow header advertising the supported
// set. After #170 the supported set is {GET, PUT, DELETE}.
func TestDCRManagement_UnsupportedMethodReturns405(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"405 Test"}`)

	for _, method := range []string{http.MethodPost, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/apps/dcr/"+registered["client_id"].(string), nil)
			req.Header.Set("Authorization", "Bearer "+registered["registration_access_token"].(string))
			rr := httptest.NewRecorder()
			registrar.Handler().ServeHTTP(rr, req)

			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
			assert.Equal(t, "GET, PUT, DELETE", rr.Header().Get("Allow"))
		})
	}
}

// --- PUT — RFC 7592 §2.2 update tests ---
//
// Issue #169 ships full-replace semantics, registration_access_token rotation,
// and rejection of token_endpoint_auth_method changes (out of scope here;
// clients change auth method via DELETE + re-register).

// TestUpdateRegistration_HappyPath_RotatesToken verifies that a successful PUT
// replaces editable metadata and rotates the registration_access_token. The
// old token MUST stop working after rotation — that's the security guarantee.
func TestUpdateRegistration_HappyPath_RotatesToken(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar,
		`{"client_name":"Pre Update","scope":"read"}`)
	clientID := registered["client_id"].(string)
	oldToken := registered["registration_access_token"].(string)

	updated, err := registrar.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{
		ClientID:    clientID,
		AccessToken: oldToken,
		Metadata: &admin.DCRRequest{
			ClientID:   clientID,
			ClientName: "Post Update",
			Scope:      "read write",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, updated.Registration)
	assert.Equal(t, "Post Update", updated.Registration.ClientName)
	assert.Equal(t, "read write", updated.Registration.Scope)

	newToken := updated.Registration.RegistrationAccessToken
	require.NotEmpty(t, newToken, "PUT must return a registration_access_token")
	assert.NotEqual(t, oldToken, newToken, "token must rotate on PUT (RFC 7592 §2.2)")

	// Old token is now invalid.
	_, err = registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
		ClientID: clientID, AccessToken: oldToken,
	})
	assert.True(t, errors.Is(err, admin.ErrUnauthorized), "old token must not survive rotation")
	// New token works.
	gotAfter, err := registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
		ClientID: clientID, AccessToken: newToken,
	})
	require.NoError(t, err)
	assert.Equal(t, "Post Update", gotAfter.Registration.ClientName)
}

// TestUpdateRegistration_WrongTokenReturnsUnauthorized verifies that a caller
// presenting a non-matching token cannot update the registration.
func TestUpdateRegistration_WrongTokenReturnsUnauthorized(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Wrong Token PUT"}`)
	clientID := registered["client_id"].(string)

	_, err := registrar.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{
		ClientID:    clientID,
		AccessToken: "definitely-wrong",
		Metadata: &admin.DCRRequest{
			ClientID:   clientID,
			ClientName: "Hacked",
		},
	})
	assert.True(t, errors.Is(err, admin.ErrUnauthorized))
}

// TestUpdateRegistration_UnknownClientReturnsUnauthorized verifies that
// unknown client_ids look the same as wrong-token failures (no enumeration).
func TestUpdateRegistration_UnknownClientReturnsUnauthorized(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	_, err := registrar.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{
		ClientID:    "app_phantom",
		AccessToken: "any",
		Metadata: &admin.DCRRequest{
			ClientID:   "app_phantom",
			ClientName: "x",
		},
	})
	assert.True(t, errors.Is(err, admin.ErrUnauthorized))
}

// TestUpdateRegistration_AuthMethodChangeRejected verifies that PUT cannot
// switch token_endpoint_auth_method (e.g., HS256 client_secret_post →
// private_key_jwt). Such a change requires re-keying and is out of scope for
// #169; clients DELETE + re-register instead.
func TestUpdateRegistration_AuthMethodChangeRejected(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Auth Method Lock"}`)
	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	_, err := registrar.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{
		ClientID:    clientID,
		AccessToken: token,
		Metadata: &admin.DCRRequest{
			ClientID:                clientID,
			ClientName:              "Auth Method Lock",
			TokenEndpointAuthMethod: "private_key_jwt", // was client_secret_post
		},
	})
	assert.True(t, errors.Is(err, admin.ErrInvalidClientMetadata))
}

// TestDCRManagement_PUT_HappyPath drives the full HTTP wrapper: success
// returns 200 + the no-store cache headers + the rotated token in the body.
func TestDCRManagement_PUT_HappyPath(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"PUT HP","scope":"read"}`)
	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	body := `{"client_id":"` + clientID + `","client_name":"PUT HP Updated","scope":"read write"}`
	req := httptest.NewRequest(http.MethodPut, "/apps/dcr/"+clientID, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, "PUT HP Updated", got["client_name"])
	assert.Equal(t, "read write", got["scope"])
	newTok, _ := got["registration_access_token"].(string)
	require.NotEmpty(t, newTok)
	assert.NotEqual(t, token, newTok, "PUT response must include rotated token")
}

// TestDCRManagement_PUT_MissingBodyClientID verifies the RFC 7592 §2.2
// requirement that the body MUST include client_id matching the URL. Wrapper
// returns 400 before the manager is invoked.
func TestDCRManagement_PUT_MissingBodyClientID(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Missing CID"}`)
	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	body := `{"client_name":"No client_id field"}` // intentionally no client_id
	req := httptest.NewRequest(http.MethodPut, "/apps/dcr/"+clientID, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestDCRManagement_PUT_BodyClientIDMismatch verifies that a body with the
// wrong client_id is rejected with 400, even when the auth token is valid.
func TestDCRManagement_PUT_BodyClientIDMismatch(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Mismatch"}`)
	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	body := `{"client_id":"app_other","client_name":"Mismatched"}`
	req := httptest.NewRequest(http.MethodPut, "/apps/dcr/"+clientID, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestDCRManagement_PUT_MalformedJSONReturns400 ensures unparsable bodies are
// surfaced as 400, not 500.
func TestDCRManagement_PUT_MalformedJSONReturns400(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Malformed"}`)
	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	req := httptest.NewRequest(http.MethodPut, "/apps/dcr/"+clientID, strings.NewReader("{not-json"))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestDCRManagement_PUT_WrongTokenReturns401 mirrors the GET wrong-token
// behavior at the wire level — uniform 401 envelope, no leakage.
func TestDCRManagement_PUT_WrongTokenReturns401(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"PUT Wrong Token"}`)
	clientID := registered["client_id"].(string)

	body := `{"client_id":"` + clientID + `","client_name":"Should fail"}`
	req := httptest.NewRequest(http.MethodPut, "/apps/dcr/"+clientID, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer not-the-real-token")
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "Bearer")
}

// --- DELETE — RFC 7592 §2.3 tests ---
//
// Issue #170 ships full deletion semantics: registration removed, signing
// credentials invalidated so already-issued tokens fail subsequent validation.

// TestDeleteRegistration_HappyPath verifies the canonical delete flow: the
// registration is gone from the store, the signing key is gone from KeyStore,
// and any subsequent management call (with the same token) returns
// ErrUnauthorized — there is no special "already deleted" signal, by design.
func TestDeleteRegistration_HappyPath(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Delete Me"}`)
	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	resp, err := registrar.DeleteRegistration(context.Background(), &admin.DeleteRegistrationRequest{
		ClientID:    clientID,
		AccessToken: token,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// Registration is gone — subsequent GETs cannot tell you anything.
	_, err = registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
		ClientID: clientID, AccessToken: token,
	})
	assert.True(t, errors.Is(err, admin.ErrUnauthorized), "post-delete GET must return ErrUnauthorized")

	// Signing key is gone — tokens issued under this client_id can no longer
	// be re-validated against the AS.
	if _, err := ks.GetKey(clientID); err != keys.ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound after delete, got %v", err)
	}
}

// TestDeleteRegistration_WrongTokenReturnsUnauthorized verifies that a caller
// presenting a non-matching token cannot delete the registration. The
// registration must remain intact afterwards.
func TestDeleteRegistration_WrongTokenReturnsUnauthorized(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"Wrong Token DELETE"}`)
	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	_, err := registrar.DeleteRegistration(context.Background(), &admin.DeleteRegistrationRequest{
		ClientID:    clientID,
		AccessToken: "definitely-not-the-token",
	})
	assert.True(t, errors.Is(err, admin.ErrUnauthorized))

	// Registration must still be readable with the legitimate token.
	resp, err := registrar.GetRegistration(context.Background(), &admin.GetRegistrationRequest{
		ClientID: clientID, AccessToken: token,
	})
	require.NoError(t, err, "registration must survive a failed delete")
	assert.Equal(t, clientID, resp.Registration.ClientID)
}

// TestDeleteRegistration_UnknownClientReturnsUnauthorized verifies the
// no-enumeration property: deleting an unknown client_id returns
// ErrUnauthorized, not a "not found" signal.
func TestDeleteRegistration_UnknownClientReturnsUnauthorized(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	_, err := registrar.DeleteRegistration(context.Background(), &admin.DeleteRegistrationRequest{
		ClientID:    "app_does_not_exist",
		AccessToken: "any",
	})
	assert.True(t, errors.Is(err, admin.ErrUnauthorized))
}

// TestDeleteRegistration_LegacyRegistrationCannotBeDeleted verifies that
// apps registered through the legacy /apps/register endpoint (no
// registration_access_token issued) are not deletable through the management
// interface — only DCR-registered clients participate in RFC 7592.
func TestDeleteRegistration_LegacyRegistrationCannotBeDeleted(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	body := `{"client_domain":"legacy.example","signing_alg":"HS256"}`
	req := httptest.NewRequest(http.MethodPost, "/apps/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)
	var legacy map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &legacy))

	_, err := registrar.DeleteRegistration(context.Background(), &admin.DeleteRegistrationRequest{
		ClientID:    legacy["client_id"].(string),
		AccessToken: "any-token",
	})
	assert.True(t, errors.Is(err, admin.ErrUnauthorized))
}

// TestDCRManagement_DELETE_HappyPath verifies the wire-level behavior: 204
// No Content with the no-store cache headers required for token-bearing
// endpoints, and an empty response body.
func TestDCRManagement_DELETE_HappyPath(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"DELETE HP"}`)
	clientID := registered["client_id"].(string)
	token := registered["registration_access_token"].(string)

	req := httptest.NewRequest(http.MethodDelete, "/apps/dcr/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Empty(t, rr.Body.String(), "204 response must have an empty body")
}

// TestDCRManagement_DELETE_WrongToken returns 401 when the Bearer value does
// not match the stored registration_access_token.
func TestDCRManagement_DELETE_WrongToken(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"DELETE Wrong Token"}`)

	req := httptest.NewRequest(http.MethodDelete, "/apps/dcr/"+registered["client_id"].(string), nil)
	req.Header.Set("Authorization", "Bearer not-the-real-token")
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestDCRManagement_DELETE_MissingAuthHeader returns 401 with no auth header.
func TestDCRManagement_DELETE_MissingAuthHeader(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registered := registerDCRClient(t, registrar, `{"client_name":"DELETE No Auth"}`)

	req := httptest.NewRequest(http.MethodDelete, "/apps/dcr/"+registered["client_id"].(string), nil)
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestDCRManagement_DELETE_UnknownClient returns 401 (not 404) — same
// no-enumeration guard as GET / PUT.
func TestDCRManagement_DELETE_UnknownClient(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	req := httptest.NewRequest(http.MethodDelete, "/apps/dcr/app_phantom", nil)
	req.Header.Set("Authorization", "Bearer something")
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
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
