package apiauth_test

// The token-side endpoints refuse repeated parameters and client
// credentials in the request URI, and read their parameters from the
// form body only. The OAuch run in issue 497 found both gaps (issue 519).
//
// References:
//   - RFC 6749 §3.1, §3.2: parameters MUST NOT be included more than once
//   - RFC 6749 §2.3.1: client credentials MUST NOT be included in the request URI
//   - RFC 8707 §2, RFC 8693 §2.1: resource and audience may repeat
//   - See: https://github.com/panyam/oneauth/issues/519

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawPost sends a form POST with a raw query string and a raw body, so a
// test can repeat a parameter or put one in the URI.
func rawPost(t *testing.T, h http.Handler, path, query, body, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	target := path
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func requireInvalidRequest(t *testing.T, rr *httptest.ResponseRecorder, mention string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	m := body(t, rr)
	assert.Equal(t, "invalid_request", m["error"])
	assert.Contains(t, m["error_description"], mention)
}

const passwordGrant = "grant_type=password&username=alice&password=right"

// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
func TestTokenEndpoint_RefusesARepeatedParameter(t *testing.T) {
	h := newPolicyEndpoint(t)
	ok := rawPost(t, h, "/api/token", "", passwordGrant+"&scope=read", openClient, openSecret)
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())

	rr := rawPost(t, h, "/api/token", "", passwordGrant+"&scope=read&scope=write", openClient, openSecret)
	requireInvalidRequest(t, rr, "scope")
}

// RFC 8707 lets a client name several resources, and the SDK does.
// See: https://www.rfc-editor.org/rfc/rfc8707#section-2
func TestTokenEndpoint_ResourceAndAudienceMayRepeat(t *testing.T) {
	h := newPolicyEndpoint(t)
	rr := rawPost(t, h, "/api/token", "",
		passwordGrant+"&resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example&audience=a&audience=b",
		openClient, openSecret)
	assert.NotContains(t, rr.Body.String(), "more than once")
}

// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
func TestTokenEndpoint_RefusesClientCredentialsInTheURI(t *testing.T) {
	h := newPolicyEndpoint(t)
	rr := rawPost(t, h, "/api/token", "client_id="+openClient+"&client_secret="+openSecret, passwordGrant, "", "")
	requireInvalidRequest(t, rr, "request URI")

	rr = rawPost(t, h, "/api/token", "client_assertion_type=x&client_assertion=y", passwordGrant, openClient, openSecret)
	requireInvalidRequest(t, rr, "request URI")
}

// Parameters in the URI are ignored, so a grant type sent only there is
// missing.
func TestTokenEndpoint_ReadsParametersFromTheBodyOnly(t *testing.T) {
	h := newPolicyEndpoint(t)
	rr := rawPost(t, h, "/api/token", "grant_type=password", "username=alice&password=right", openClient, openSecret)
	assert.NotEqual(t, http.StatusOK, rr.Code, rr.Body.String())
}

// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
func TestIntrospectionAndRevocation_RefuseCredentialsInTheURIAndRepeats(t *testing.T) {
	rev, _, intro := setupRevocation(t)
	for name, h := range map[string]http.Handler{"introspection": intro, "revocation": rev} {
		t.Run(name, func(t *testing.T) {
			ok := rawPost(t, h, "/oauth/x", "", "token=abc", "revoke-client", "revoke-client-secret")
			require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())

			rr := rawPost(t, h, "/oauth/x", "client_id=revoke-client&client_secret=revoke-client-secret", "token=abc", "", "")
			requireInvalidRequest(t, rr, "request URI")

			rr = rawPost(t, h, "/oauth/x", "", "token=abc&token=def", "revoke-client", "revoke-client-secret")
			requireInvalidRequest(t, rr, "token")
		})
	}
}

// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.1
func TestDeviceAuthorization_RefusesCredentialsInTheURIAndRepeats(t *testing.T) {
	h := newBasicAuthDeviceAuthzHandler(t, "client-conf", "conf-secret")
	ok := rawPost(t, h, "/device", "", "scope=read", "client-conf", "conf-secret")
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())

	rr := rawPost(t, h, "/device", "client_id=client-conf&client_secret=conf-secret", "scope=read", "", "")
	requireInvalidRequest(t, rr, "request URI")

	rr = rawPost(t, h, "/device", "", "scope=read&scope=write", "client-conf", "conf-secret")
	requireInvalidRequest(t, rr, "scope")
}

// See: https://www.rfc-editor.org/rfc/rfc9126#section-2.1
func TestPAR_RefusesCredentialsInTheURIAndRepeats(t *testing.T) {
	f := newPARFixture(t)
	form := parForm(nil)
	ok := rawPost(t, f.handler, parEndpointURL, "", form.Encode(), "", "")
	require.Equal(t, http.StatusCreated, ok.Code, ok.Body.String())

	rr := rawPost(t, f.handler, parEndpointURL, "client_secret=s", form.Encode(), "", "")
	requireInvalidRequest(t, rr, "request URI")

	rr = rawPost(t, f.handler, parEndpointURL, "", form.Encode()+"&scope=write", "", "")
	requireInvalidRequest(t, rr, "scope")
}

// A JSON token request is refused too when the URI carries a secret.
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
func TestTokenEndpoint_RefusesCredentialsInTheURIForJSONBodies(t *testing.T) {
	h := newPolicyEndpoint(t)
	req := httptest.NewRequest(http.MethodPost, "/api/token?client_secret="+openSecret,
		strings.NewReader(`{"grant_type":"password","username":"alice","password":"right","client_id":"`+openClient+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	requireInvalidRequest(t, rr, "request URI")
}

// A client_id in the URI is not read, so it can't pair with a secret in
// the body.
func TestTokenEndpoint_IgnoresClientIDInTheURI(t *testing.T) {
	h := newPolicyEndpoint(t)
	ok := rawPost(t, h, "/api/token", "", "grant_type=client_credentials&client_id="+openClient+"&client_secret="+openSecret, "", "")
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())

	rr := rawPost(t, h, "/api/token", "client_id="+openClient, "grant_type=client_credentials&client_secret="+openSecret, "", "")
	assert.NotEqual(t, http.StatusOK, rr.Code, rr.Body.String())
}
