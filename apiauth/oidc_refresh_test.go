package apiauth_test

// ID tokens on the refresh grant (OIDC Core §12.2): an openid grant gets a
// fresh ID token on every refresh, which repeats the original login
// rather than describing the refresh, and the §5.5 claims request keeps
// applying to the ID token and to userinfo (issue 485).
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

func refreshOIDC(t *testing.T, fx *oidcFixture, refreshToken string) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {authcodeTestClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	return decodeJSON(t, rr)
}

func TestOIDCRefresh_IDTokenRepeatsTheOriginalLogin(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	authTime := time.Now().Add(-time.Hour).Truncate(time.Second)
	seedOIDCCode(t, fx.codes, []string{"openid", "read"}, "n-0S6_WzA2Mj", authTime)
	first := redeemOIDC(t, fx)
	require.NotEmpty(t, first["refresh_token"])

	refreshed := refreshOIDC(t, fx, first["refresh_token"].(string))
	raw, _ := refreshed["id_token"].(string)
	require.NotEmpty(t, raw, "an openid grant gets an ID token on refresh")

	claims := verifyIDToken(t, fx, raw)
	original := verifyIDToken(t, fx, first["id_token"].(string))
	assert.Equal(t, original["sub"], claims["sub"], "§12.2: same sub")
	assert.Equal(t, float64(authTime.Unix()), claims["auth_time"], "§12.2: auth_time of the original login")
	assert.Nil(t, claims["nonce"], "the refresh request carries no nonce")
	sum := sha256.Sum256([]byte(refreshed["access_token"].(string)))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:16]), claims["at_hash"], "bound to the refreshed access token")

	again := refreshOIDC(t, fx, refreshed["refresh_token"].(string))
	assert.Equal(t, float64(authTime.Unix()), verifyIDToken(t, fx, again["id_token"].(string))["auth_time"], "and after another rotation")
}

func TestOIDCRefresh_ClaimsRequestOutlivesTheRefresh(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	first := authorizeAndRedeem(t, fx, claimsParams("openid", `{"id_token":{"email":null},"userinfo":{"name":null}}`))

	refreshed := refreshOIDC(t, fx, first["refresh_token"].(string))
	assert.Equal(t, authcodeTestSubject+"@example.com", verifyIDToken(t, fx, refreshed["id_token"].(string))["email"])

	rr := callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", refreshed["access_token"].(string), "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "Test User", decodeJSON(t, rr)["name"], "the refreshed access token still asks userinfo for name")
}

func TestOIDCRefresh_NoOpenIDNoIDToken(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	seedOIDCCode(t, fx.codes, []string{"read"}, "", time.Time{})
	first := redeemOIDC(t, fx)

	refreshed := refreshOIDC(t, fx, first["refresh_token"].(string))
	assert.Nil(t, refreshed["id_token"])
}

// A refreshed access token still names its client, so userinfo gives a
// pairwise client the same sub as before the refresh, and as the
// refreshed ID token (§5.3.2).
func TestOIDCRefresh_PairwiseSubjectSurvivesTheRefresh(t *testing.T) {
	fx := pairwiseFixture(t, "pairwise", pairwiseSalt)
	seedOIDCCode(t, fx.codes, []string{"openid"}, "", time.Time{})
	first := redeemOIDC(t, fx)

	refreshed := refreshOIDC(t, fx, first["refresh_token"].(string))
	want := apiauth.PairwiseSubject(pairwiseSalt, "app.example", authcodeTestSubject)
	assert.Equal(t, want, verifyIDToken(t, fx, refreshed["id_token"].(string))["sub"])
	assert.Equal(t, want, userinfoSub(t, fx, refreshed["access_token"].(string)))
}
