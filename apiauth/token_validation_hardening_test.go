package apiauth_test

// Access-token validation, issue 88's "Token Security" walk: what the
// validator and the resource middleware must refuse even when the signature
// checks out.
//
// References:
//   - RFC 8725 §3.1, §3.11 (https://www.rfc-editor.org/rfc/rfc8725)
//   - RFC 7519 §4.1.4 (https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)
//   - RFC 7518 §3.2 key size (https://www.rfc-editor.org/rfc/rfc7518#section-3.2)
//   - RFC 6750 §3.1 (https://www.rfc-editor.org/rfc/rfc6750#section-3.1)
//   - RFC 9728 §5.1 (https://www.rfc-editor.org/rfc/rfc9728#section-5.1)
//   - CVE-2015-9235, CWE-347 (https://cwe.mitre.org/data/definitions/347.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const (
	hardenSecret = "hardening-test-secret-32-bytes!!"
	hardenIssuer = "https://as.example.com"
)

func signHS256(t *testing.T, key []byte, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	for k, v := range header {
		tok.Header[k] = v
	}
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func accessClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "alice", "iss": hardenIssuer, "type": "access", "scopes": []string{"read"},
		"jti": "j1", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
}

func hardenValidator() apiauth.TokenValidator {
	return apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{SigningKey: []byte(hardenSecret), Issuer: hardenIssuer})
}

func validate(v apiauth.TokenValidator, token string) error {
	_, err := v.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	return err
}

func callMiddleware(mw *apiauth.APIMiddleware, h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// An empty HMAC key verifies any token signed with the empty key, so a
// middleware with no secret configured must not validate inline at all.
//
// See: https://www.rfc-editor.org/rfc/rfc7518#section-3.2
func TestHardening_EmptyHMACKeyNeverVerifies(t *testing.T) {
	forged := signHS256(t, []byte(""), accessClaims(), nil)

	mw := &apiauth.APIMiddleware{JWTIssuer: hardenIssuer}
	rr := callMiddleware(mw, mw.ValidateToken(okHandler()), forged)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	v := apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{SigningKey: []byte(""), Issuer: hardenIssuer})
	assert.Error(t, validate(v, forged))
}

// A token without exp would be valid forever.
//
// See: https://www.rfc-editor.org/rfc/rfc8725#section-3.10
func TestHardening_ExpIsRequired(t *testing.T) {
	claims := accessClaims()
	delete(claims, "exp")
	tok := signHS256(t, []byte(hardenSecret), claims, nil)

	assert.Error(t, validate(hardenValidator(), tok))
	mw := &apiauth.APIMiddleware{JWTSecretKey: hardenSecret, JWTIssuer: hardenIssuer}
	assert.Equal(t, http.StatusUnauthorized, callMiddleware(mw, mw.ValidateToken(okHandler()), tok).Code)
}

// Other JWTs the AS signs with the same key (back-channel logout tokens,
// ID-JAGs, browser sessions) must not pass as access tokens, even with a
// valid signature, issuer and subject.
//
// See: https://www.rfc-editor.org/rfc/rfc8725#section-3.11
func TestHardening_OtherJWTKindsAreNotAccessTokens(t *testing.T) {
	cases := map[string]struct {
		header map[string]any
		mutate func(jwt.MapClaims)
	}{
		"logout token (typ logout+jwt)":  {map[string]any{"typ": "logout+jwt"}, func(c jwt.MapClaims) { delete(c, "type") }},
		"ID-JAG (typ oauth-id-jag+jwt)":  {map[string]any{"typ": apiauth.IDJAGTypeHeader}, func(c jwt.MapClaims) { delete(c, "type") }},
		"browser session (type session)": {nil, func(c jwt.MapClaims) { c["type"] = "session" }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			claims := accessClaims()
			tc.mutate(claims)
			tok := signHS256(t, []byte(hardenSecret), claims, tc.header)

			assert.Error(t, validate(hardenValidator(), tok), "validator")
			mw := &apiauth.APIMiddleware{JWTSecretKey: hardenSecret, JWTIssuer: hardenIssuer}
			assert.Equal(t, http.StatusUnauthorized, callMiddleware(mw, mw.ValidateToken(okHandler()), tok).Code, "middleware")
		})
	}

	// Access tokens with an ordinary or RFC 9068 typ still pass.
	for _, typ := range []string{"JWT", "at+jwt", "application/at+jwt"} {
		tok := signHS256(t, []byte(hardenSecret), accessClaims(), map[string]any{"typ": typ})
		assert.NoError(t, validate(hardenValidator(), tok), typ)
	}
}

// A tenant (registered app) key may only sign tokens for that tenant: a
// token signed with app A's key must say client_id A. Without the claim it
// could speak for anyone the AS's own tokens speak for.
//
// See: https://cwe.mitre.org/data/definitions/347.html
func TestHardening_TenantKeySignsOnlyForItsTenant(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	appSecret := []byte("app-a-secret-that-is-32-bytes-ok")
	_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app-a", Key: appSecret, Algorithm: "HS256"}})
	require.NoError(t, err)
	appKid, err := utils.ComputeKid(appSecret, "HS256")
	require.NoError(t, err)
	v := apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{KeyLookup: ks, SigningKey: []byte(hardenSecret), Issuer: hardenIssuer})

	claims := accessClaims()
	forged := signHS256(t, appSecret, claims, map[string]any{"kid": appKid})
	assert.Error(t, validate(v, forged), "app A's key, no client_id claim")

	claims["client_id"] = "app-a"
	own := signHS256(t, appSecret, claims, map[string]any{"kid": appKid})
	assert.NoError(t, validate(v, own), "app A's key, client_id app-a")

	// The AS's own tokens carry no client_id when a grant had none.
	asKid, err := utils.ComputeKid([]byte(hardenSecret), "HS256")
	require.NoError(t, err)
	asToken := signHS256(t, []byte(hardenSecret), accessClaims(), map[string]any{"kid": asKid})
	assert.NoError(t, validate(v, asToken), "the AS's own token")

	mw := &apiauth.APIMiddleware{KeyStore: ks, JWTIssuer: hardenIssuer}
	assert.Equal(t, http.StatusUnauthorized, callMiddleware(mw, mw.ValidateToken(okHandler()), forged).Code, "middleware")
}

// CustomClaimsFunc cannot overwrite the claims a resource server makes
// authorization decisions on.
func TestHardening_CustomClaimsCannotOverrideAuthorizationClaims(t *testing.T) {
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		SigningKey: []byte(hardenSecret), SigningAlg: "HS256", Issuer: hardenIssuer,
		CustomClaims: func(string, []string) (map[string]any, error) {
			return map[string]any{
				"client_id": "evil", "nbf": 1, "scope": "admin", "act": map[string]any{"sub": "x"},
				"may_act": map[string]any{"sub": "x"}, "azp": "evil", "sid": "s", "team": "blue",
			}, nil
		},
	})
	resp, err := oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "alice", ClientID: "real", Scopes: []string{"read"}})
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(resp.Token, claims)
	require.NoError(t, err)

	assert.Equal(t, "real", claims["client_id"])
	for _, k := range []string{"nbf", "scope", "act", "may_act", "azp", "sid"} {
		assert.NotContains(t, claims, k, k)
	}
	assert.Equal(t, "blue", claims["team"], "non-reserved custom claims still pass through")
}

// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
func TestHardening_BearerChallenges(t *testing.T) {
	mw := &apiauth.APIMiddleware{JWTSecretKey: hardenSecret, JWTIssuer: hardenIssuer, ResourceMetadataURL: "https://api.example.com/.well-known/oauth-protected-resource"}

	t.Run("no token: no error code", func(t *testing.T) {
		rr := callMiddleware(mw, mw.ValidateToken(okHandler()), "")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		h := rr.Header().Get("WWW-Authenticate")
		assert.NotContains(t, h, "error=")
		assert.Contains(t, h, `resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`)
	})
	t.Run("bad token: invalid_token", func(t *testing.T) {
		rr := callMiddleware(mw, mw.ValidateToken(okHandler()), "not-a-jwt")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		h := rr.Header().Get("WWW-Authenticate")
		assert.True(t, strings.HasPrefix(h, `Bearer realm="api", `), h)
		assert.Contains(t, h, `, error="invalid_token"`)
	})
	t.Run("missing scope: 403 insufficient_scope", func(t *testing.T) {
		tok := signHS256(t, []byte(hardenSecret), accessClaims(), nil)
		rr := callMiddleware(mw, mw.RequireScopes("admin")(okHandler()), tok)
		assert.Equal(t, http.StatusForbidden, rr.Code)
		h := rr.Header().Get("WWW-Authenticate")
		assert.True(t, strings.HasPrefix(h, `Bearer realm="api", `), h)
		assert.Contains(t, h, `, error="insufficient_scope"`)
		assert.Contains(t, h, `, scope="admin"`)
	})
}
