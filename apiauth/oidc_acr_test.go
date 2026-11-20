package apiauth_test

// acr and amr in ID tokens (OIDC Core §2, §3.1.2.1, issue 485). The
// deployment says how the user logged in through AuthContextFromRequest,
// which sees the client's acr_values. The ID token reports the result,
// and so does every ID token a refresh of the grant issues (§12.2).
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// See: https://www.rfc-editor.org/rfc/rfc8176

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

// acrMux mounts /authorize with a password-only deployment: it meets
// acr "1", and reports it when the client asks for it.
func acrMux(fx *oidcFixture, consent bool, seen *[]string) *http.ServeMux {
	mux := http.NewServeMux()
	cfg := apiauth.AuthorizeMountConfig{
		OneAuth:              fx.OneAuth,
		IssuerURL:            oidcIssuer,
		AllowAnyRedirectURI:  true,
		SubjectFromRequest:   func(*http.Request) string { return authcodeTestSubject },
		AuthTimeFromRequest:  func(*http.Request) time.Time { return time.Now() },
		CSRFTokenFromRequest: func(*http.Request) string { return "" },
		AuthContextFromRequest: func(_ *http.Request, acrValues []string) apiauth.AuthContext {
			if seen != nil {
				*seen = acrValues
			}
			ac := apiauth.AuthContext{AMR: []string{"pwd"}}
			if slices.Contains(acrValues, "1") {
				ac.ACR = "1"
			}
			return ac
		},
	}
	if !consent {
		cfg.AutoApproveSubject = authcodeTestSubject
	}
	apiauth.MountAuthorize(mux, cfg)
	return mux
}

func TestOIDC_ACRAndAMRFromTheAuthContext(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	q := claimsParams("openid", "")
	q.Set("acr_values", "2 1")
	var seen []string
	tok := authorizeAndRedeemOn(t, fx, acrMux(fx, false, &seen), q)

	assert.Equal(t, []string{"2", "1"}, seen, "the hook sees acr_values in preference order")
	claims := verifyIDToken(t, fx, tok["id_token"].(string))
	assert.Equal(t, "1", claims["acr"])
	assert.Equal(t, []any{"pwd"}, claims["amr"])

	refreshed := refreshOIDC(t, fx, tok["refresh_token"].(string))
	again := verifyIDToken(t, fx, refreshed["id_token"].(string))
	assert.Equal(t, "1", again["acr"], "§12.2: a refresh repeats the login's acr")
	assert.Equal(t, []any{"pwd"}, again["amr"])
}

func TestOIDC_NoACRWhenTheHookGivesNone(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	tok := authorizeAndRedeemOn(t, fx, acrMux(fx, false, nil), claimsParams("openid", ""))
	claims := verifyIDToken(t, fx, tok["id_token"].(string))
	assert.Nil(t, claims["acr"])
	assert.Equal(t, []any{"pwd"}, claims["amr"])
}

// The consent page posts the request back, so acr_values has to be a
// hidden input or the hook never sees it at Approve.
func TestOIDC_ConsentFormCarriesACRValues(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	q := claimsParams("openid", "")
	q.Set("acr_values", "1 2")
	rr := httptest.NewRecorder()
	acrMux(fx, true, nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), `<input type="hidden" name="acr_values" value="1 2">`)
}
