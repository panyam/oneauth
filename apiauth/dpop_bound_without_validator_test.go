package apiauth_test

// RFC 9449 §7.2: a resource server refuses a DPoP-bound access token
// presented as a bearer token. A middleware without a DPoP validator
// can't check a proof, so it refuses any token bound to a key, rather
// than accept it as Bearer.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.2
// See: https://github.com/panyam/oneauth/issues/486

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareWithoutDPoP_RefusesABoundToken(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	bound, _ := mintAccess(t, fx, []string{"openid"}, "some-thumbprint")
	plain, _ := mintAccess(t, fx, []string{"openid"}, "")
	h := fx.OneAuth.UserinfoHTTPHandler(nil)

	rr := callUserinfo(h, http.MethodGet, "Bearer", bound, "")
	assert.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`)

	req := httptest.NewRequest(http.MethodPost, rsBaseURL+"/userinfo", strings.NewReader(url.Values{"access_token": {bound}}.Encode()))
	req.URL.Path = "/userinfo"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body := httptest.NewRecorder()
	h.ServeHTTP(body, req)
	assert.Equal(t, http.StatusUnauthorized, body.Code, "the form body is a Bearer presentation too")

	require.Equal(t, http.StatusOK, callUserinfo(h, http.MethodGet, "Bearer", plain, "").Code, "an unbound token still works")
}
