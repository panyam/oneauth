package main

// jwt.signing_alg: PS256 (issue 330). The server signs with an RSA key
// under RSASSA-PSS, the JWKS lists the key as PS256, and discovery says
// PS256 wherever it names the AS signing algorithm. FAPI 2.0 §5.4.1
// accepts it, as it does ES256.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
// See: https://github.com/panyam/oneauth/issues/330

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ps256Signing = fapiBase + "  signing_alg: PS256\n  ephemeral_signing_key: true\n"

func TestPS256Server_EphemeralKeyIsRSA(t *testing.T) {
	priv, _, err := loadOrGenerateSigningKey(JWTConfig{EphemeralSigningKey: true}, "PS256")
	require.NoError(t, err)
	_, ok := priv.(*rsa.PrivateKey)
	assert.True(t, ok, "PS256 needs an RSA key, got %T", priv)
}

func TestPS256Server_FAPI2AcceptsIt(t *testing.T) {
	cfg := loadYAML(t, ps256Signing+"fapi2: true\ndpop:\n  enabled: true\n")
	assert.NoError(t, checkFAPI2(cfg))
	meta := serverASMetadata(cfg, "https://as.example", false)
	assert.Equal(t, []string{"PS256", "ES256"}, meta.TokenEndpointAuthSigningAlgValuesSupported, "a FAPI client may register a PS256 key")
}

func TestPS256Server_JWKSAndDiscoverySayPS256(t *testing.T) {
	cfg := loadYAML(t, ps256Signing+"admin_auth:\n  type: none\n  allow_open: true\ncode_flow:\n  enabled: true\n  oidc: true\n  jarm:\n    enabled: true\n")
	require.NoError(t, checkOIDC(cfg))
	require.NoError(t, checkJARM(cfg))
	handler, cleanup, err := buildServer(cfg)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	getJSON(t, srv.URL+"/.well-known/jwks.json", &jwks)
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "RSA", jwks.Keys[0]["kty"])
	assert.Equal(t, "PS256", jwks.Keys[0]["alg"])

	var meta map[string]any
	getJSON(t, srv.URL+"/.well-known/openid-configuration", &meta)
	assert.Equal(t, []any{"PS256"}, meta["id_token_signing_alg_values_supported"])
	assert.Equal(t, []any{"PS256"}, meta["authorization_signing_alg_values_supported"])
	assert.Contains(t, meta["token_endpoint_auth_signing_alg_values_supported"], "PS256")
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, url)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
}
