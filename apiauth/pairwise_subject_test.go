package apiauth_test

// Pairwise subject identifiers (OIDC Core §8.1, issue 507): a client
// registered as pairwise gets a sub derived from its sector, the same in
// the ID token and at userinfo, so two sectors can't match up a user.
// Access tokens keep the user's own ID, which resource servers key on.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
// See: https://github.com/panyam/oneauth/issues/507

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

var pairwiseSalt = []byte("pairwise-salt-for-tests-32-bytes!")

func TestPairwiseSubject_Derivation(t *testing.T) {
	a := apiauth.PairwiseSubject(pairwiseSalt, "app.example", "user-1")
	assert.Equal(t, a, apiauth.PairwiseSubject(pairwiseSalt, "app.example", "user-1"), "stable")
	assert.NotEqual(t, a, apiauth.PairwiseSubject(pairwiseSalt, "other.example", "user-1"), "per sector")
	assert.NotEqual(t, a, apiauth.PairwiseSubject(pairwiseSalt, "app.example", "user-2"), "per user")
	assert.NotEqual(t, a, apiauth.PairwiseSubject([]byte("another-salt-another-salt-32-bytes"), "app.example", "user-1"), "per server")
	assert.NotContains(t, a, "user-1")
	_, err := base64.RawURLEncoding.DecodeString(a)
	assert.NoError(t, err, "a URL-safe string, at most 255 ASCII characters (§2)")
	// The separator stops ("a.b", "c") and ("a", "b.c")-style collisions.
	assert.NotEqual(t, apiauth.PairwiseSubject(pairwiseSalt, "ab", "c"), apiauth.PairwiseSubject(pairwiseSalt, "a", "bc"))
}

// pairwiseFixture is the OIDC fixture with the test client registered as
// subjectType in the app store, and the pairwise salt set when salt is.
func pairwiseFixture(t *testing.T, subjectType string, salt []byte) *oidcFixture {
	t.Helper()
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: authcodeTestClientID, RedirectURIs: []string{authcodeTestRedirect}, TokenEndpointAuthMethod: "none",
		SubjectType: subjectType, SectorIdentifier: "app.example",
	}})
	require.NoError(t, err)
	return newOIDCFixtureWith(t, nil, func(c *apiauth.OneAuthConfig) {
		c.AppStore = apps
		c.OIDC.PairwiseSalt = salt
	})
}

func userinfoSub(t *testing.T, fx *oidcFixture, accessToken string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+accessToken)
	fx.OneAuth.UserinfoHTTPHandler(nil).ServeHTTP(rr, r)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	return decodeJSON(t, rr)["sub"].(string)
}

func TestOIDC_PairwiseClientGetsItsSectorsSubject(t *testing.T) {
	fx := pairwiseFixture(t, "pairwise", pairwiseSalt)
	seedOIDCCode(t, fx.codes, []string{"openid"}, "", time.Time{})
	body := redeemOIDC(t, fx)

	want := apiauth.PairwiseSubject(pairwiseSalt, "app.example", authcodeTestSubject)
	assert.Equal(t, want, verifyIDToken(t, fx, body["id_token"].(string))["sub"])
	assert.Equal(t, want, userinfoSub(t, fx, body["access_token"].(string)), "userinfo and the ID token agree (§5.3.2)")

	info, err := fx.OneAuth.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: body["access_token"].(string)})
	require.NoError(t, err)
	assert.Equal(t, authcodeTestSubject, info.Info.Subject, "access tokens keep the user's own ID for resource servers")
}

func TestOIDC_PublicClientGetsTheUserID(t *testing.T) {
	fx := pairwiseFixture(t, "public", pairwiseSalt)
	seedOIDCCode(t, fx.codes, []string{"openid"}, "", time.Time{})
	body := redeemOIDC(t, fx)
	assert.Equal(t, authcodeTestSubject, verifyIDToken(t, fx, body["id_token"].(string))["sub"])
	assert.Equal(t, authcodeTestSubject, userinfoSub(t, fx, body["access_token"].(string)))
}

// A pairwise client on a server with no salt gets no ID token rather than
// one carrying the user's real ID.
func TestOIDC_PairwiseWithoutSaltFailsClosed(t *testing.T) {
	fx := pairwiseFixture(t, "pairwise", nil)
	seedOIDCCode(t, fx.codes, []string{"openid"}, "", time.Time{})
	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, tokenRedeemForm(t, nil))
	assert.NotEqual(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "id_token")
}

// A short salt would make pairwise subs guessable for anyone who knows a
// user's ID, so the server refuses to start with one.
func TestNewOneAuth_ShortPairwiseSaltPanics(t *testing.T) {
	assert.Panics(t, func() { pairwiseFixture(t, "pairwise", []byte("too-short")) })
}
