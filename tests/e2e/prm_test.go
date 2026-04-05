package e2e_test

// Tests for the Protected Resource Metadata (RFC 9728) endpoint on resource servers.
// Verifies that clients can auto-discover resource server capabilities via
// GET /.well-known/oauth-protected-resource — including which auth servers are
// trusted, supported scopes, token formats, and signing algorithms.
//
// References:
//   - RFC 9728 (https://www.rfc-editor.org/rfc/rfc9728):
//     "OAuth 2.0 Protected Resource Metadata"
//   - See: https://github.com/panyam/oneauth/issues/46

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPRM_ResourceServerA_Discovery verifies that resource server A serves
// Protected Resource Metadata at the well-known endpoint. This is the primary
// e2e test for PRM: a client hits the resource server and discovers its
// capabilities without any prior configuration.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3
func TestPRM_ResourceServerA_Discovery(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("PRM e2e test requires in-process resource servers")
	}

	resp, err := http.Get(env.ResourceAURL() + "/.well-known/oauth-protected-resource")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, resp.Header.Get("Cache-Control"), "public")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var meta map[string]any
	require.NoError(t, json.Unmarshal(body, &meta))

	// Required fields
	assert.NotEmpty(t, meta["resource"], "resource field is required")
	servers, ok := meta["authorization_servers"].([]any)
	require.True(t, ok, "authorization_servers must be an array")
	assert.NotEmpty(t, servers, "authorization_servers must not be empty")

	// Authorization server should point to our auth server
	assert.Equal(t, env.BaseURL(), servers[0].(string),
		"authorization_servers[0] should be the auth server URL")

	// Optional fields — our e2e resource servers advertise these
	assert.NotEmpty(t, meta["scopes_supported"])
	assert.NotEmpty(t, meta["token_formats_supported"])
	assert.NotEmpty(t, meta["resource_signing_alg_values_supported"])
}

// TestPRM_ResourceServerB_Discovery verifies that resource server B also
// serves PRM independently. This confirms that each resource server
// advertises its own metadata, supporting the multi-resource-server
// federated architecture.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3
func TestPRM_ResourceServerB_Discovery(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("PRM e2e test requires in-process resource servers")
	}

	resp, err := http.Get(env.ResourceBURL() + "/.well-known/oauth-protected-resource")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	// Both resource servers should trust the same auth server
	servers := meta["authorization_servers"].([]any)
	assert.Equal(t, env.BaseURL(), servers[0].(string))

	// But they have different resource identifiers
	assert.Contains(t, meta["resource"].(string), "resource-b",
		"resource-b should identify itself distinctly")
}

// TestPRM_MethodNotAllowed_E2E verifies that POST to the PRM endpoint is
// rejected with 405. This ensures the endpoint is read-only in the
// deployed configuration.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3
func TestPRM_MethodNotAllowed_E2E(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("PRM e2e test requires in-process resource servers")
	}

	resp, err := http.Post(env.ResourceAURL()+"/.well-known/oauth-protected-resource", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}
