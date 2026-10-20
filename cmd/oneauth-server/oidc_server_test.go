package main

// The reference server as an OpenID Provider (code_flow.oidc): discovery
// names the userinfo endpoint and ID token algorithm, a logged-in user's
// `openid` code redeems to an ID token a client can verify against the
// JWKS, and /userinfo answers for the access token beside it.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
// See: https://github.com/panyam/oneauth/issues/339

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

func newOIDCServerFixture(t *testing.T) *loginFixture {
	t.Helper()
	return newLoginFixtureConfig(t, "  signing_alg: ES256\n  ephemeral_signing_key: true", "  oidc: true")
}

func TestOIDCServer_CodeFlowIssuesAVerifiableIDToken(t *testing.T) {
	f := newOIDCServerFixture(t)

	_, disc := f.get(t, "/.well-known/openid-configuration")
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(disc), &meta))
	assert.Equal(t, f.url+"/userinfo", meta["userinfo_endpoint"])
	assert.Equal(t, []any{"ES256"}, meta["id_token_signing_alg_values_supported"])
	assert.Contains(t, meta["claims_supported"], "email_verified")

	before := time.Now().Add(-time.Second)
	authorize := f.authorizePath() + "&" + url.Values{"scope": {"openid email"}, "nonce": {"n-server-339"}}.Encode()
	tok := redeemCodeAt(t, f, approveCode(t, f, authorize))

	// Verify the way a relying party would: the key comes from the JWKS
	// discovery points at, not from the server's config.
	jwks := keys.NewJWKSKeyStore(meta["jwks_uri"].(string))
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tok["id_token"].(string), claims, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		rec, err := jwks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: kid})
		if err != nil {
			return nil, err
		}
		if pem, ok := rec.Record.Key.([]byte); ok {
			return utils.DecodeVerifyKey(pem, "ES256")
		}
		return rec.Record.Key, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(f.url), jwt.WithAudience(f.clientID))
	require.NoError(t, err)
	assert.Equal(t, "n-server-339", claims["nonce"])
	assert.Equal(t, loginTestEmail, claims["email"])
	assert.Equal(t, false, claims["email_verified"], "signup sent no verification, so the address is unconfirmed")
	authTime, ok := claims["auth_time"].(float64)
	require.True(t, ok, "auth_time comes from the session cookie: %v", claims)
	assert.GreaterOrEqual(t, int64(authTime), before.Unix())

	req, _ := http.NewRequest(http.MethodGet, f.url+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	uresp, err := f.http.Do(req)
	require.NoError(t, err)
	defer uresp.Body.Close()
	require.Equal(t, http.StatusOK, uresp.StatusCode)
	var info map[string]any
	require.NoError(t, json.NewDecoder(uresp.Body).Decode(&info))
	assert.Equal(t, claims["sub"], info["sub"])
	assert.Equal(t, loginTestEmail, info["email"])
}

// Without code_flow.oidc the server is a plain OAuth AS: no ID token, no
// userinfo route, and discovery does not claim either.
func TestOIDCServer_OffByDefault(t *testing.T) {
	f := newLoginFixtureWith(t, "  signing_alg: ES256\n  ephemeral_signing_key: true")
	_, disc := f.get(t, "/.well-known/openid-configuration")
	assert.NotContains(t, disc, "userinfo_endpoint")
	assert.NotContains(t, disc, "id_token_signing_alg_values_supported")
	resp, _ := f.get(t, "/userinfo")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestOIDCServer_RefusesHMACSigning(t *testing.T) {
	cfg := loadYAML(t, `
jwt:
  secret_key: "oidc-hmac-test-secret-32-bytes!!"
code_flow:
  enabled: true
  oidc: true
`)
	err := checkOIDC(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code_flow.oidc needs jwt.signing_alg RS256 or ES256")
}
