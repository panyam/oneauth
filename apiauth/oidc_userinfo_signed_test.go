package apiauth_test

// Signed userinfo responses (OIDC Core §5.3.2, issue 485). A client
// registered with userinfo_signed_response_alg gets userinfo as a JWT
// signed by the AS key, carrying iss and aud so it can't be replayed to
// another client. Other clients keep getting plain JSON.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

import (
	"context"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func signedUserinfoFixture(t *testing.T, alg string) *oidcFixture {
	t.Helper()
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: authcodeTestClientID, RedirectURIs: []string{authcodeTestRedirect}, TokenEndpointAuthMethod: "none",
		UserinfoSignedResponseAlg: alg,
	}})
	require.NoError(t, err)
	return newOIDCFixtureWith(t, testUserClaims, func(c *apiauth.OneAuthConfig) { c.AppStore = apps })
}

func TestUserinfo_SignedForAClientThatRegisteredAnAlg(t *testing.T) {
	fx := signedUserinfoFixture(t, "ES256")
	tok, _ := mintAccess(t, fx, []string{"openid", "email"}, "")

	rr := callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", tok, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "application/jwt", rr.Header().Get("Content-Type"))

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(rr.Body.String(), claims, func(*jwt.Token) (any, error) { return &fx.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(oidcIssuer), jwt.WithAudience(authcodeTestClientID))
	require.NoError(t, err, "verifies against the AS key, with iss and aud (§5.3.2)")
	assert.NotEmpty(t, parsed.Header["kid"], "the client picks the key from the JWKS by kid")
	assert.Equal(t, authcodeTestSubject, claims["sub"])
	assert.Equal(t, authcodeTestSubject+"@example.com", claims["email"])
}

func TestUserinfo_PlainJSONForAClientThatRegisteredNoAlg(t *testing.T) {
	fx := signedUserinfoFixture(t, "")
	tok, _ := mintAccess(t, fx, []string{"openid"}, "")

	rr := callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", tok, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

// An alg the AS doesn't sign with can only come from a store edited
// behind DCR's back. The endpoint refuses rather than answering in a
// form the client didn't register for.
func TestUserinfo_UnsupportedRegisteredAlgFailsClosed(t *testing.T) {
	fx := signedUserinfoFixture(t, "RS256")
	tok, _ := mintAccess(t, fx, []string{"openid"}, "")

	rr := callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", tok, "")
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.NotContains(t, rr.Body.String(), authcodeTestSubject)
}

func TestOneAuth_UserinfoSigningAlgsIsTheSigningAlg(t *testing.T) {
	assert.Equal(t, []string{"ES256"}, newOIDCFixture(t, nil).OneAuth.UserinfoSigningAlgs())
}
