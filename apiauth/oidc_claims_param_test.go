package apiauth_test

// The OIDC Core §5.5 `claims` request parameter: a client asks for claims
// by name, for the ID token, for userinfo, or both, on top of what its
// scopes grant.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
// See: https://github.com/panyam/oneauth/issues/453

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

// authorizeMux mounts /authorize on fx's OneAuth with the test subject
// auto-approved, or showing the consent page when consent is true.
func authorizeMux(fx *oidcFixture, consent bool) *http.ServeMux {
	mux := http.NewServeMux()
	cfg := apiauth.AuthorizeMountConfig{
		OneAuth:              fx.OneAuth,
		IssuerURL:            oidcIssuer,
		AllowAnyRedirectURI:  true,
		SubjectFromRequest:   func(*http.Request) string { return authcodeTestSubject },
		AuthTimeFromRequest:  func(*http.Request) time.Time { return time.Now() },
		CSRFTokenFromRequest: func(*http.Request) string { return "" },
	}
	if !consent {
		cfg.AutoApproveSubject = authcodeTestSubject
	}
	apiauth.MountAuthorize(mux, cfg)
	return mux
}

func claimsParams(scope, claims string) url.Values {
	q := url.Values{
		"client_id":             {authcodeTestClientID},
		"redirect_uri":          {authcodeTestRedirect},
		"response_type":         {"code"},
		"scope":                 {scope},
		"state":                 {"st"},
		"code_challenge":        {core.ComputeCodeChallenge(authcodeTestVerifier)},
		"code_challenge_method": {core.CodeChallengeMethodS256},
	}
	if claims != "" {
		q.Set("claims", claims)
	}
	return q
}

// authorizeAndRedeem runs the request through /authorize and redeems the
// code, returning the token response.
func authorizeAndRedeem(t *testing.T, fx *oidcFixture, q url.Values) map[string]any {
	t.Helper()
	return authorizeAndRedeemOn(t, fx, authorizeMux(fx, false), q)
}

// authorizeAndRedeemOn is authorizeAndRedeem through mux's /authorize.
func authorizeAndRedeemOn(t *testing.T, fx *oidcFixture, mux http.Handler, q url.Values) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "redirect %s", loc)

	tr := httptest.NewRecorder()
	fx.ServeHTTP(tr, tokenRedeemForm(t, url.Values{"code": {code}}))
	require.Equal(t, http.StatusOK, tr.Code, tr.Body.String())
	return decodeJSON(t, tr)
}

// Claims asked for in the ID token are added to it, though the scopes
// alone (just openid) grant none of them.
func TestClaimsParam_IDTokenGetsRequestedClaims(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	tok := authorizeAndRedeem(t, fx, claimsParams("openid", `{"id_token":{"name":{"essential":true},"email":null}}`))

	claims := verifyIDToken(t, fx, tok["id_token"].(string))
	assert.Equal(t, "Test User", claims["name"])
	assert.Equal(t, authcodeTestSubject+"@example.com", claims["email"])
	assert.Nil(t, claims["email_verified"], "only the claims asked for by name")
}

// Claims asked for at userinfo come back from userinfo, and stay out of
// the ID token.
func TestClaimsParam_UserinfoGetsRequestedClaims(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	tok := authorizeAndRedeem(t, fx, claimsParams("openid", `{"userinfo":{"name":{"essential":true}}}`))

	assert.Nil(t, verifyIDToken(t, fx, tok["id_token"].(string))["name"])
	rr := callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", tok["access_token"].(string), "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	body := decodeJSON(t, rr)
	assert.Equal(t, "Test User", body["name"])
	assert.Nil(t, body["email"], "neither asked for nor granted by scope")
}

// Scope claims and requested claims add up.
func TestClaimsParam_AddsToTheScopeClaims(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	tok := authorizeAndRedeem(t, fx, claimsParams("openid email", `{"userinfo":{"name":null}}`))

	body := decodeJSON(t, callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", tok["access_token"].(string), ""))
	assert.Equal(t, "Test User", body["name"])
	assert.Equal(t, authcodeTestSubject+"@example.com", body["email"])
}

// A claims value that isn't the §5.5 JSON object is invalid_request at
// the redirect URI.
func TestClaimsParam_MalformedIsInvalidRequest(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	for _, bad := range []string{`not json`, `["name"]`, `{"userinfo":"name"}`, `{"id_token":{"name":"yes"}}`} {
		rr := httptest.NewRecorder()
		authorizeMux(fx, false).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+claimsParams("openid", bad).Encode(), nil))
		require.Equal(t, http.StatusFound, rr.Code, "%s: %s", bad, rr.Body.String())
		loc, _ := url.Parse(rr.Header().Get("Location"))
		assert.Equal(t, "invalid_request", loc.Query().Get("error"), bad)
	}
}

// The consent page posts the request back, and Approve re-reads it, so
// the claims parameter has to be a hidden input or it's lost at Approve.
func TestClaimsParam_ConsentFormCarriesClaims(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	rr := httptest.NewRecorder()
	authorizeMux(fx, true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+claimsParams("openid", `{"userinfo":{"name":null}}`).Encode(), nil))
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `name="claims" value="{&#34;userinfo&#34;:{&#34;name&#34;:null}}"`)
}

// A CustomClaimsFunc can't set the claim that carries the userinfo
// request, or it could hand a token claims its client never asked for.
func TestClaimsParam_CustomClaimsCannotSetTheUserinfoRequest(t *testing.T) {
	fx := newOIDCFixtureWith(t, testUserClaims, func(cfg *apiauth.OneAuthConfig) {
		cfg.CustomClaims = func(string, []string) (map[string]any, error) {
			return map[string]any{"oa_userinfo_claims": []string{"name"}}, nil
		}
	})
	token, _ := mintAccess(t, fx, []string{"openid"}, "")

	body := decodeJSON(t, callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", token, ""))
	assert.Nil(t, body["name"])
}

// RFC 6750 §2.2: userinfo accepts the access token as a form-encoded
// `access_token` body parameter on POST (OIDC Core §5.3.1).
// See: https://www.rfc-editor.org/rfc/rfc6750#section-2.2
func TestUserinfo_AccessTokenInFormBody(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	h := fx.OneAuth.UserinfoHTTPHandler(nil)
	token, _ := mintAccess(t, fx, []string{"openid", "email"}, "")

	post := func(contentType, body, header string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, rsBaseURL+"/userinfo", strings.NewReader(body))
		req.URL.Path = "/userinfo"
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	form := url.Values{"access_token": {token}}.Encode()

	rr := post("application/x-www-form-urlencoded", form, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, authcodeTestSubject+"@example.com", decodeJSON(t, rr)["email"])

	// §2.2 is for form bodies only.
	assert.Equal(t, http.StatusUnauthorized, post("application/json", `{"access_token":"`+token+`"}`, "").Code)
	// §2: a client MUST NOT use more than one method in a request.
	rr = post("application/x-www-form-urlencoded", form, "Bearer "+token)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_request"`)
	// A bad token in the body is refused like a bad header.
	assert.Equal(t, http.StatusUnauthorized, post("application/x-www-form-urlencoded", url.Values{"access_token": {"nope"}}.Encode(), "").Code)

	// GET has no body, and the URI query form (§2.3) stays unsupported.
	req := httptest.NewRequest(http.MethodGet, rsBaseURL+"/userinfo?access_token="+token, nil)
	req.URL.Path = "/userinfo"
	get := httptest.NewRecorder()
	h.ServeHTTP(get, req)
	assert.Equal(t, http.StatusUnauthorized, get.Code)
}

// A DPoP-bound token sent in the body is a Bearer presentation, which RFC
// 9449 §7.2 refuses for a bound token at a DPoP-aware middleware.
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.2
func TestUserinfo_DPoPBoundTokenInFormBodyIsRefused(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	mw := fx.OneAuth.HTTPMiddleware()
	mw.DPoP = apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: rsBaseURL})
	token, _ := mintAccess(t, fx, []string{"openid"}, "some-thumbprint")
	req := httptest.NewRequest(http.MethodPost, rsBaseURL+"/userinfo", strings.NewReader(url.Values{"access_token": {token}}.Encode()))
	req.URL.Path = "/userinfo"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	fx.OneAuth.UserinfoHTTPHandler(mw).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `DPoP error="invalid_token"`)
}
