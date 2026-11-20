package main

// trusted_assertion_issuers turns on the RFC 7523 §2.1 jwt-bearer grant and
// RFC 8693 token exchange for JWTs from listed upstream IdPs (issue 521).
// The MCP enterprise-managed authorization flow uses both.
//
// See: https://www.rfc-editor.org/rfc/rfc7523#section-2.1
// See: https://www.rfc-editor.org/rfc/rfc8693#section-2.1

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	trustedTestIssuer = "https://as.test"
	upstreamIdP       = "https://idp.test"
)

func trustedIssuerServer(t *testing.T, issuersYAML string) *httptest.Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.yaml")
	cfg := fmt.Sprintf(`jwt:
  issuer: %s
  signing_alg: ES256
  ephemeral_signing_key: true
  secret_key: trusted-issuer-test-secret-32-bytes!
keystore:
  type: memory
user_stores:
  type: memory
admin_auth:
  type: none
  allow_open: true
%s`, trustedTestIssuer, issuersYAML)
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	c, err := LoadConfig(path)
	require.NoError(t, err)
	handler, cleanup, err := buildServer(c)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func upstreamKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pem, err := utils.EncodePublicKeyPEM(&key.PublicKey)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "idp.pub.pem")
	require.NoError(t, os.WriteFile(path, pem, 0o600))
	return key, path
}

func assertion(t *testing.T, key *rsa.PrivateKey, iss, aud string) string {
	t.Helper()
	jti := rand.Text()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": iss, "sub": "alice", "aud": aud, "jti": jti,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func grantTypes(t *testing.T, base string) []any {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	defer resp.Body.Close()
	meta := map[string]any{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	gt, _ := meta["grant_types_supported"].([]any)
	return gt
}

func postToken(t *testing.T, base string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(base+"/api/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	body := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestTrustedAssertionIssuers_AdvertiseAndRedeemBothGrants(t *testing.T) {
	key, pubPath := upstreamKey(t)
	srv := trustedIssuerServer(t, fmt.Sprintf(`trusted_assertion_issuers:
  - issuer: %s
    public_key_path: %s
`, upstreamIdP, pubPath))

	gt := grantTypes(t, srv.URL)
	assert.Contains(t, gt, "urn:ietf:params:oauth:grant-type:jwt-bearer")
	assert.Contains(t, gt, "urn:ietf:params:oauth:grant-type:token-exchange")

	status, body := postToken(t, srv.URL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion(t, key, upstreamIdP, trustedTestIssuer)},
	})
	require.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["access_token"])

	status, body = postToken(t, srv.URL, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {assertion(t, key, upstreamIdP, trustedTestIssuer+"/api/token")},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
	})
	require.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["access_token"])
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", body["issued_token_type"])
}

func TestTrustedAssertionIssuers_RefuseOtherIssuersAndAudiences(t *testing.T) {
	key, pubPath := upstreamKey(t)
	srv := trustedIssuerServer(t, fmt.Sprintf(`trusted_assertion_issuers:
  - issuer: %s
    public_key_path: %s
`, upstreamIdP, pubPath))
	for name, a := range map[string]string{
		"another issuer":                 assertion(t, key, "https://evil.test", trustedTestIssuer),
		"an audience that isn't this AS": assertion(t, key, upstreamIdP, "https://mcp.example/mcp"),
	} {
		status, body := postToken(t, srv.URL, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {a},
		})
		assert.Equal(t, http.StatusBadRequest, status, name)
		assert.Equal(t, "invalid_grant", body["error"], name)
	}
}

func TestTrustedAssertionIssuers_OffByDefault(t *testing.T) {
	gt := grantTypes(t, trustedIssuerServer(t, "").URL)
	assert.NotContains(t, gt, "urn:ietf:params:oauth:grant-type:jwt-bearer")
	assert.NotContains(t, gt, "urn:ietf:params:oauth:grant-type:token-exchange")
}

func TestTrustedAssertionIssuers_BadEntriesStopStartup(t *testing.T) {
	_, pubPath := upstreamKey(t)
	for name, entry := range map[string]string{
		"no key":        "  - issuer: " + upstreamIdP + "\n",
		"no issuer":     "  - public_key_path: " + pubPath + "\n",
		"two keys":      "  - issuer: " + upstreamIdP + "\n    public_key_path: " + pubPath + "\n    jwks_uri: https://idp.test/jwks\n",
		"missing file":  "  - issuer: " + upstreamIdP + "\n    public_key_path: /no/such/key.pem\n",
		"symmetric alg": "  - issuer: " + upstreamIdP + "\n    public_key_path: " + pubPath + "\n    accepted_algorithms: [HS256]\n",
	} {
		path := filepath.Join(t.TempDir(), "c.yaml")
		require.NoError(t, os.WriteFile(path, []byte("keystore:\n  type: memory\nuser_stores:\n  type: memory\nadmin_auth:\n  type: none\n  allow_open: true\ntrusted_assertion_issuers:\n"+entry), 0o600))
		c, err := LoadConfig(path)
		if err == nil {
			_, cleanup, berr := buildServer(c)
			if cleanup != nil {
				cleanup()
			}
			err = berr
		}
		assert.Error(t, err, name)
	}
}

// A jwks_uri issuer's assertions are verified with the key their kid names,
// so the IdP can rotate keys without a config change.
func TestTrustedAssertionIssuers_JWKSURI(t *testing.T) {
	key, _ := upstreamKey(t)
	kid, err := utils.ComputeKid(&key.PublicKey, "RS256")
	require.NoError(t, err)
	jwk, err := utils.PublicKeyToJWK(kid, "RS256", &key.PublicKey)
	require.NoError(t, err)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(utils.JWKSet{Keys: []utils.JWK{jwk}})
	}))
	t.Cleanup(idp.Close)
	srv := trustedIssuerServer(t, fmt.Sprintf("trusted_assertion_issuers:\n  - issuer: %s\n    jwks_uri: %s\n", upstreamIdP, idp.URL))

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": upstreamIdP, "sub": "alice", "aud": trustedTestIssuer, "jti": rand.Text(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	status, body := postToken(t, srv.URL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signed},
	})
	assert.Equal(t, http.StatusOK, status, body)
}
