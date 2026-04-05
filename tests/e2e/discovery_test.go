package e2e_test

// End-to-end tests for OAuth AS Metadata Discovery (RFC 8414).
// Verifies that the auth server serves /.well-known/openid-configuration
// and that the client-side DiscoverAS function can parse it.
//
// This closes the discovery loop: #50 (server) + #51 (client) working together.
//
// References:
//   - RFC 8414 (https://www.rfc-editor.org/rfc/rfc8414):
//     "OAuth 2.0 Authorization Server Metadata"
//   - See: https://github.com/panyam/oneauth/issues/50

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/panyam/oneauth/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiscovery_E2E_OIDCConfiguration verifies that the auth server serves
// valid OIDC discovery metadata at /.well-known/openid-configuration.
// This is the raw HTTP test — verifies structure, content-type, caching.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-3
func TestDiscovery_E2E_OIDCConfiguration(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("discovery e2e requires in-process servers")
	}

	resp, err := http.Get(env.BaseURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, resp.Header.Get("Cache-Control"), "public")

	body, _ := io.ReadAll(resp.Body)
	var meta map[string]any
	require.NoError(t, json.Unmarshal(body, &meta))

	// Required fields
	assert.Equal(t, env.BaseURL(), meta["issuer"])
	assert.NotEmpty(t, meta["token_endpoint"])
	assert.NotEmpty(t, meta["jwks_uri"])

	// Endpoints should point to the auth server
	assert.Contains(t, meta["token_endpoint"].(string), env.BaseURL())
	assert.Contains(t, meta["jwks_uri"].(string), env.BaseURL())

	// Grant types we support
	grants := meta["grant_types_supported"].([]any)
	assert.Contains(t, grants, "password")
	assert.Contains(t, grants, "refresh_token")
	assert.Contains(t, grants, "client_credentials")
}

// TestDiscovery_E2E_DiscoverASRoundTrip verifies that the client-side
// DiscoverAS function (#51) correctly discovers endpoints from our auth
// server's OIDC discovery endpoint (#50). This is the full round-trip:
// server serves metadata → client discovers it.
//
// See: https://www.rfc-editor.org/rfc/rfc8414
func TestDiscovery_E2E_DiscoverASRoundTrip(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("discovery e2e requires in-process servers")
	}

	meta, err := client.DiscoverAS(env.BaseURL())
	require.NoError(t, err, "DiscoverAS should find our auth server's OIDC config")

	assert.Equal(t, env.BaseURL(), meta.Issuer)
	assert.Equal(t, env.BaseURL()+"/api/token", meta.TokenEndpoint)
	assert.Equal(t, env.BaseURL()+"/.well-known/jwks.json", meta.JWKSURI)
	assert.Equal(t, env.BaseURL()+"/oauth/introspect", meta.IntrospectionEndpoint)
	assert.Contains(t, meta.GrantTypesSupported, "client_credentials")
	assert.Contains(t, meta.TokenEndpointAuthMethods, "client_secret_post")
}

// TestDiscovery_E2E_MethodNotAllowed verifies that POST to the discovery
// endpoint is rejected.
func TestDiscovery_E2E_MethodNotAllowed(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("discovery e2e requires in-process servers")
	}

	resp, err := http.Post(env.BaseURL()+"/.well-known/openid-configuration",
		"application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}
