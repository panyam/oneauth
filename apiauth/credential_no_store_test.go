package apiauth_test

// Cache-Control: no-store on every response that carries a credential or a
// token error. RFC 6749 §5.1 requires it on token responses, and OAuth 2.1
// §3.2.4 extends it to errors; an API key is shown once, at creation, and
// must not be left in a cache either.
//
// References:
//   - RFC 6749 §5.1 (https://www.rfc-editor.org/rfc/rfc6749#section-5.1)
//   - OAuth 2.1 §3.2.4 (https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-3.2.4)
//   - CWE-525 (https://cwe.mitre.org/data/definitions/525.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func requireNoStore(t *testing.T, h http.Header, what string) {
	t.Helper()
	assert.Equal(t, "no-store", h.Get("Cache-Control"), "%s must not be cacheable", what)
	assert.Equal(t, "no-cache", h.Get("Pragma"), what)
}

func TestNoStore_TokenEndpointErrors(t *testing.T) {
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{SigningKey: []byte("server-jwt-secret-key-32chars!!"), SigningAlg: "HS256"}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader("grant_type=bogus"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	fx.TokenEndpoint.ServeHTTP(rr, req)

	require.Equal(t, "unsupported_grant_type", decodeJSON(t, rr)["error"])
	requireNoStore(t, rr.Header(), "a token endpoint error")
}

func TestNoStore_DeviceAuthorizationErrors(t *testing.T) {
	h := newBasicAuthDeviceAuthzHandler(t, "client-conf", "conf-secret")
	status, _ := postFormBasic(t, h, url.Values{"scope": {"read"}}, "client-conf", "wrong")
	require.NotEqual(t, http.StatusOK, status)

	req := httptest.NewRequest(http.MethodPost, "/device/authorize", strings.NewReader("scope=read"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client-conf", "wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	requireNoStore(t, rr.Header(), "a device authorization error")
}

func TestNoStore_APIKeyCreation(t *testing.T) {
	fx, _, _, userID := setupAPIAuthTest(t)
	body, _ := json.Marshal(map[string]any{"name": "k", "scopes": []string{"read"}})
	req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(core.SetSubjectInContext(req.Context(), userID))
	rr := httptest.NewRecorder()
	fx.HandleAPIKeys(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), `"api_key"`)
	requireNoStore(t, rr.Header(), "a new API key")
}
