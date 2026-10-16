package main

// The reference server's `dpop:` config block (issue 395 item 3): YAML in,
// validators out, and the same refusals the library gives when the config
// can't work.
//
// See: https://www.rfc-editor.org/rfc/rfc9449
// See: https://github.com/panyam/oneauth/issues/395

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/utils"
)

func loadYAML(t *testing.T, body string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	return cfg
}

func TestDPoPConfig_ParsesTheBlock(t *testing.T) {
	cfg := loadYAML(t, `
jwt:
  disable_refresh_token_rotation: true
dpop:
  enabled: true
  profile: fapi
  require: true
  require_at_resource: true
  max_age: 45s
  nonce:
    required: true
    secret: "s3cret-nonce-key"
    lifetime: 2m
`)
	d := cfg.DPoP
	assert.True(t, d.Enabled)
	assert.Equal(t, "fapi", d.Profile)
	assert.True(t, d.Require)
	assert.True(t, d.RequireAtResource)
	assert.Equal(t, 45*time.Second, d.MaxAge)
	assert.True(t, d.Nonce.Required)
	assert.Equal(t, "s3cret-nonce-key", d.Nonce.Secret)
	assert.Equal(t, 2*time.Minute, d.Nonce.Lifetime)
	assert.True(t, cfg.JWT.DisableRefreshTokenRotation)
}

func TestDPoPConfig_DisabledBuildsNothing(t *testing.T) {
	w, err := buildDPoP(DPoPServerConfig{}, "https://as.example.com")
	require.NoError(t, err)
	assert.Nil(t, w.tokenEndpoint)
	assert.Nil(t, w.resource)
}

func TestDPoPConfig_FAPIProfileAlgs(t *testing.T) {
	w, err := buildDPoP(DPoPServerConfig{Enabled: true, Profile: "fapi"}, "https://as.example.com")
	require.NoError(t, err)
	assert.ElementsMatch(t, apiauth.FAPIDPoPAlgs(), w.tokenEndpoint.SigningAlgValuesSupported())
	assert.ElementsMatch(t, apiauth.FAPIDPoPAlgs(), w.resource.SigningAlgValuesSupported())
}

func TestDPoPConfig_ExplicitAlgs(t *testing.T) {
	w, err := buildDPoP(DPoPServerConfig{Enabled: true, Algs: []string{"ES256"}}, "https://as.example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"ES256"}, w.tokenEndpoint.SigningAlgValuesSupported())
}

// A config that can't do what it says fails at startup rather than serving
// something weaker.
func TestDPoPConfig_RefusesBrokenConfig(t *testing.T) {
	for name, c := range map[string]DPoPServerConfig{
		"require without enabled":             {Require: true},
		"require_at_resource without enabled": {RequireAtResource: true},
		"nonce without enabled":               {Nonce: DPoPNonceConfig{Required: true}},
		"unknown profile":                     {Enabled: true, Profile: "fapi3"},
		"profile and algs both set":           {Enabled: true, Profile: "fapi", Algs: []string{"ES256"}},
		"symmetric alg":                       {Enabled: true, Algs: []string{"HS256"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildDPoP(c, "https://as.example.com")
			assert.Error(t, err)
		})
	}
}

// The token-endpoint validator checks htu against the public token endpoint
// URL, which is what makes DPoP work behind a TLS-terminating proxy.
func TestDPoPConfig_TokenEndpointHTUIsThePublicURL(t *testing.T) {
	w, err := buildDPoP(DPoPServerConfig{Enabled: true}, "https://as.example.com")
	require.NoError(t, err)
	key, err := client.NewDPoPKey()
	require.NoError(t, err)

	proof, err := key.Proof(http.MethodPost, "https://as.example.com/api/token", "")
	require.NoError(t, err)
	// The request arrives over plain http from the proxy, on another host.
	r := httptest.NewRequest(http.MethodPost, "http://10.0.0.5:8080/api/token", nil)
	r.Header.Set("DPoP", proof)
	cnf, err := w.tokenEndpoint.Confirm(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), cnf.JKT)
}

// With nonces required, a proof without one is answered with a nonce
// challenge, and the configured secret makes the nonce verifiable by
// another process with the same config.
func TestDPoPConfig_NonceRequired(t *testing.T) {
	c := DPoPServerConfig{Enabled: true, Nonce: DPoPNonceConfig{Required: true, Secret: "shared-secret"}}
	a, err := buildDPoP(c, "https://as.example.com")
	require.NoError(t, err)
	b, err := buildDPoP(c, "https://as.example.com")
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := client.NewDPoPKeyFromECDSA(ecKey)
	require.NoError(t, err)

	proof, err := key.Proof(http.MethodPost, "https://as.example.com/api/token", "")
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/api/token", nil)
	r.Header.Set("DPoP", proof)
	_, err = a.tokenEndpoint.Confirm(context.Background(), r)
	var nonceErr *apiauth.NonceRequiredError
	require.True(t, errors.As(err, &nonceErr), "got %v", err)
	require.NotEmpty(t, nonceErr.Nonce)

	// A proof carrying the nonce from process a passes process b.
	withNonce := mintWithNonce(t, ecKey, "https://as.example.com/api/token", nonceErr.Nonce)
	r2 := httptest.NewRequest(http.MethodPost, "https://as.example.com/api/token", nil)
	r2.Header.Set("DPoP", withNonce)
	_, err = b.tokenEndpoint.Confirm(context.Background(), r2)
	assert.NoError(t, err)
}

// mintWithNonce signs a token-endpoint proof carrying a server nonce. The
// SDK keeps that step internal, so the test signs it by hand.
func mintWithNonce(t *testing.T, key *ecdsa.PrivateKey, htu, nonce string) string {
	t.Helper()
	jti := make([]byte, 16)
	_, err := rand.Read(jti)
	require.NoError(t, err)
	encoded, err := json.Marshal(utils.ECDSAPublicKeyToJWK("", "ES256", &key.PublicKey))
	require.NoError(t, err)
	var jwk map[string]any
	require.NoError(t, json.Unmarshal(encoded, &jwk))
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"jti": base64.RawURLEncoding.EncodeToString(jti), "htm": http.MethodPost, "htu": htu,
		"iat": time.Now().Unix(), "nonce": nonce,
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

// The shipped FAPI example loads and builds.
func TestDPoPConfig_FAPIExampleLoads(t *testing.T) {
	cfg, err := LoadConfig("deploy-examples/fapi-dpop.yaml")
	require.NoError(t, err)
	assert.True(t, cfg.DPoP.Enabled)
	assert.True(t, cfg.DPoP.Require)
	assert.True(t, cfg.JWT.DisableRefreshTokenRotation)
	w, err := buildDPoP(cfg.DPoP, publicBaseURL(cfg))
	require.NoError(t, err)
	assert.ElementsMatch(t, apiauth.FAPIDPoPAlgs(), w.tokenEndpoint.SigningAlgValuesSupported())
}
