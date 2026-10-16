package admin_test

// DCR metadata validation, issue 88's "Input Validation" walk: redirect
// URIs are real https (or loopback / private-use) URLs, a bad one is
// invalid_redirect_uri, the auth method and grant types are ones the AS
// supports, what's echoed is what's stored, and a public client gets no
// secret.
//
// References:
//   - RFC 7591 §2, §3.2.2 (https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2)
//   - RFC 6749 §3.1.2 (https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2)
//   - RFC 9126 §6 (https://www.rfc-editor.org/rfc/rfc9126#section-6)
//   - CWE-20 (https://cwe.mitre.org/data/definitions/20.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

func dcrPost(t *testing.T, body string) (*admin.AppRegistrar, *keys.InMemoryKeyStore, int, map[string]any) {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registrar.IssuerBaseURL = "http://example.com"
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	registrar.Handler().ServeHTTP(rr, req)
	resp := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	return registrar, ks, rr.Code, resp
}

// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
func TestDCRValidation_BadRedirectURIs(t *testing.T) {
	for name, uri := range map[string]string{
		"userinfo":   "https://user:pass@app.example/cb",
		"empty host": "https:///cb",
		"fragment":   "https://app.example/cb#frag",
		"plain http": "http://app.example/cb",
	} {
		_, _, code, resp := dcrPost(t, `{"client_name":"x","redirect_uris":["`+uri+`"]}`)
		assert.Equal(t, http.StatusBadRequest, code, name)
		assert.Equal(t, "invalid_redirect_uri", resp["error"], name)
	}
}

// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
func TestDCRValidation_UnknownAuthMethodAndGrantType(t *testing.T) {
	_, _, code, resp := dcrPost(t, `{"client_name":"x","token_endpoint_auth_method":"tls_client_auth"}`)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_client_metadata", resp["error"])

	_, _, code, resp = dcrPost(t, `{"client_name":"x","grant_types":["client_credentials","implicit"]}`)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_client_metadata", resp["error"])

	// A public client can't use client_credentials: it has nothing to
	// authenticate with.
	_, _, code, _ = dcrPost(t, `{"client_name":"x","token_endpoint_auth_method":"none","grant_types":["client_credentials"]}`)
	assert.Equal(t, http.StatusBadRequest, code)

	// authorization_code needs somewhere to send the code.
	_, _, code, _ = dcrPost(t, `{"client_name":"x","grant_types":["authorization_code"]}`)
	assert.Equal(t, http.StatusBadRequest, code)
}

// The method in the response is the one the AS stored, and the RFC 7591 §2
// default is client_secret_basic. The response used to say
// client_secret_post while "" was stored, so a client reading its own
// registration back saw something different from what it was told.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
func TestDCRValidation_EchoedAuthMethodIsTheStoredOne(t *testing.T) {
	registrar, _, code, resp := dcrPost(t, `{"client_name":"x"}`)
	require.Equal(t, http.StatusCreated, code)
	assert.Equal(t, "client_secret_basic", resp["token_endpoint_auth_method"])
	stored, err := registrar.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: resp["client_id"].(string)})
	require.NoError(t, err)
	assert.Equal(t, "client_secret_basic", stored.App.TokenEndpointAuthMethod, "stored, not just echoed")
}

// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
func TestDCRValidation_PublicClientGetsNoSecret(t *testing.T) {
	_, ks, code, resp := dcrPost(t, `{"client_name":"x","token_endpoint_auth_method":"none","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"]}`)
	require.Equal(t, http.StatusCreated, code, resp)
	_, hasSecret := resp["client_secret"]
	assert.False(t, hasSecret, "a public client has no secret to keep")
	_, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: resp["client_id"].(string)})
	assert.Error(t, err, "and none is stored for it")
}

// See: https://www.rfc-editor.org/rfc/rfc9126#section-6
func TestDCRValidation_RequirePushedAuthorizationRequestsRoundTrips(t *testing.T) {
	registrar, _, code, resp := dcrPost(t, `{"client_name":"x","require_pushed_authorization_requests":true}`)
	require.Equal(t, http.StatusCreated, code)
	assert.Equal(t, true, resp["require_pushed_authorization_requests"])
	stored, err := registrar.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: resp["client_id"].(string)})
	require.NoError(t, err)
	assert.True(t, stored.App.RequirePushedAuthorizationRequests)
}
