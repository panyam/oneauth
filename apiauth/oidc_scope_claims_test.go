package apiauth_test

// OIDC Core §5.4: when an access token is issued, the claims the profile,
// email, address and phone scopes grant come from userinfo, and the ID
// token carries them only when the claims parameter asks (§5.5).
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
// See: https://github.com/panyam/oneauth/issues/480

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDC_ScopeClaimsStayOutOfTheIDToken(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	seedOIDCCode(t, fx.codes, []string{"openid", "email", "profile"}, "n-480", time.Time{})
	tok := redeemOIDC(t, fx)

	claims := verifyIDToken(t, fx, tok["id_token"].(string))
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "email_verified")
	assert.NotContains(t, claims, "name")
	assert.Equal(t, "n-480", claims["nonce"], "the protocol claims are still there")

	rr := callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", tok["access_token"].(string), "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	info := decodeJSON(t, rr)
	assert.Equal(t, authcodeTestSubject+"@example.com", info["email"], "userinfo serves the scope claims")
	assert.Equal(t, "Test User", info["name"])
}

func TestOIDC_IDTokenCarriesScopeClaimsAskedForByName(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	seedOIDCCodeAsking(t, fx.codes, []string{"openid", "email"}, "n-480", time.Time{}, []string{"email"})
	claims := verifyIDToken(t, fx, redeemOIDC(t, fx)["id_token"].(string))
	assert.Equal(t, authcodeTestSubject+"@example.com", claims["email"])
	assert.NotContains(t, claims, "email_verified", "only what was named")
}
