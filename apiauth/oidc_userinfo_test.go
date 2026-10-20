package apiauth_test

// The OIDC Core §5.3 userinfo endpoint: who may call it, and which claims
// it hands back for the access token's scopes.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
// See: https://github.com/panyam/oneauth/issues/339

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
)

// testUserClaims hands out an email and a name, gated by scope the way
// a real claims function would.
func testUserClaims(_ context.Context, subject string, scopes []string) (map[string]any, error) {
	return core.FilterClaimsByScope(map[string]any{
		"email":          subject + "@example.com",
		"email_verified": true,
		"name":           "Test User",
	}, scopes), nil
}

func mintAccess(t *testing.T, fx *oidcFixture, scopes []string, jkt string) (token, jti string) {
	t.Helper()
	req := &apiauth.CreateAccessTokenRequest{Subject: authcodeTestSubject, ClientID: authcodeTestClientID, Scopes: scopes}
	if jkt != "" {
		req.Confirmation = &core.Confirmation{JKT: jkt}
	}
	resp, err := fx.OneAuth.Issuer.CreateAccessToken(context.Background(), req)
	require.NoError(t, err)
	return resp.Token, resp.TokenID
}

func callUserinfo(h http.Handler, method, scheme, token, proof string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, rsBaseURL+"/userinfo", nil)
	req.URL.Path = "/userinfo"
	if token != "" {
		req.Header.Set("Authorization", scheme+" "+token)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestUserinfo_ReturnsScopedClaims(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	h := fx.OneAuth.UserinfoHTTPHandler(nil)

	// §5.3.1: the endpoint MUST support both GET and POST.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		token, _ := mintAccess(t, fx, []string{"openid", "email"}, "")
		rr := callUserinfo(h, method, "Bearer", token, "")
		require.Equal(t, http.StatusOK, rr.Code, method+": "+rr.Body.String())
		body := decodeJSON(t, rr)
		assert.Equal(t, authcodeTestSubject, body["sub"])
		assert.Equal(t, authcodeTestSubject+"@example.com", body["email"])
		assert.Equal(t, true, body["email_verified"])
		assert.Nil(t, body["name"], "profile was not granted, so name stays out")
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	}
}

// The userinfo endpoint is an OpenID resource: an access token from a
// plain OAuth grant, without "openid", does not reach it.
func TestUserinfo_RequiresTheOpenIDScope(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	token, _ := mintAccess(t, fx, []string{"email"}, "")

	rr := callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", token, "")

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
}

func TestUserinfo_RefusesMissingAndRevokedTokens(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	h := fx.OneAuth.UserinfoHTTPHandler(nil)

	assert.Equal(t, http.StatusUnauthorized, callUserinfo(h, http.MethodGet, "", "", "").Code)

	token, _ := mintAccess(t, fx, []string{"openid"}, "")
	_, err := fx.OneAuth.Revoker.Revoke(context.Background(), &apiauth.RevokeRequest{Token: token, TokenTypeHint: "access_token"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, callUserinfo(h, http.MethodGet, "Bearer", token, "").Code)
}

// An ID token is not an access token, so it does not open userinfo either.
func TestUserinfo_RefusesAnIDToken(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	idTokens := fx.OneAuth.IDTokenIssuer
	resp, err := idTokens.CreateIDToken(context.Background(), &apiauth.CreateIDTokenRequest{
		Subject: authcodeTestSubject, ClientID: authcodeTestClientID, Scopes: []string{"openid", "email"},
	})
	require.NoError(t, err)

	rr := callUserinfo(fx.OneAuth.UserinfoHTTPHandler(nil), http.MethodGet, "Bearer", resp.Token, "")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// A DPoP-bound access token reaches userinfo with its proof, and is
// refused when presented as a bearer token (RFC 9449 §7.2).
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7
func TestUserinfo_DPoPBoundToken(t *testing.T) {
	fx := newOIDCFixture(t, testUserClaims)
	mw := fx.OneAuth.HTTPMiddleware()
	mw.DPoP = apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: rsBaseURL})
	h := fx.OneAuth.UserinfoHTTPHandler(mw)

	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	token, _ := mintAccess(t, fx, []string{"openid", "email"}, jkt)

	proof := resourceProof(t, sign, token, proofOpts{url: rsBaseURL + "/userinfo"})
	rr := callUserinfo(h, http.MethodGet, "DPoP", token, proof)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, authcodeTestSubject+"@example.com", decodeJSON(t, rr)["email"])

	rr = callUserinfo(h, http.MethodGet, "Bearer", token, "")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `DPoP error="invalid_token"`)
}

func TestUserinfo_PanicsWithoutOIDC(t *testing.T) {
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{SigningKey: []byte("userinfo-test-secret-32-chars!!!"), Issuer: oidcIssuer}, nil)
	assert.Panics(t, func() { fx.OneAuth.UserinfoHTTPHandler(nil) })
}
