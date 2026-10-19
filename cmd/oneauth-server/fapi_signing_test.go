package main

// FAPI 2.0 lets an authorization server sign with PS256, ES256 or EdDSA
// only. oneauth signs access tokens with RS256 or ES256, so a fapi2 server
// has to use ES256, and the ephemeral dev key has to be one ES256 can use.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
// See: https://www.rfc-editor.org/rfc/rfc7518#section-3.4
// See: https://github.com/panyam/oneauth/issues/441

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigningKey_EphemeralKeyMatchesTheAlgorithm(t *testing.T) {
	priv, _, err := loadOrGenerateSigningKey(JWTConfig{EphemeralSigningKey: true}, "ES256")
	require.NoError(t, err)
	ec, ok := priv.(*ecdsa.PrivateKey)
	require.True(t, ok, "ES256 needs an EC key, got %T", priv)
	assert.Equal(t, elliptic.P256(), ec.Curve)

	priv, _, err = loadOrGenerateSigningKey(JWTConfig{EphemeralSigningKey: true}, "RS256")
	require.NoError(t, err)
	_, ok = priv.(*rsa.PrivateKey)
	assert.True(t, ok, "RS256 needs an RSA key, got %T", priv)
}

func TestFAPIServer_RefusesSigningAlgsFAPIDoesntAllow(t *testing.T) {
	const fapiOn = "fapi2: true\ndpop:\n  enabled: true\n"
	for _, alg := range []string{"", "HS256", "RS256"} {
		cfg := loadYAML(t, fapiBase+"  signing_alg: "+alg+"\n  ephemeral_signing_key: true\n"+fapiOn)
		err := checkFAPI2(cfg)
		require.Error(t, err, "signing_alg %q", alg)
		assert.Contains(t, err.Error(), "jwt.signing_alg")
	}
	cfg := loadYAML(t, fapiSigning+fapiOn)
	assert.NoError(t, checkFAPI2(cfg))
}

func TestFAPIServer_ExampleConfigPublishesAnES256Key(t *testing.T) {
	t.Setenv("JWT_PRIVATE_KEY_PATH", "")
	cfg, err := LoadConfig("deploy-examples/fapi-dpop.yaml")
	require.NoError(t, err)
	assert.Equal(t, "ES256", cfg.JWT.SigningAlg)

	handler, cleanup, err := buildServer(cfg)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	require.NoError(t, err)
	defer resp.Body.Close()
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwks))
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "EC", jwks.Keys[0]["kty"])
	assert.Equal(t, "ES256", jwks.Keys[0]["alg"])
}
