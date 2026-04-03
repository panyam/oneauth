package e2e_test

// Federated auth flow — register app, mint resource token, resource server validates.
// These tests were SKIPPED in the Python integration tests (5 of 53) because
// resource servers failed to start reliably. With in-process httptest servers,
// they work perfectly — no JWKS timing race.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519 (JWT)

import (
	"net/http"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFederated_MintAndValidate registers an app, mints a resource token,
// and validates it against the resource server via JWKS.
func TestFederated_MintAndValidate(t *testing.T) {
	env := NewTestEnv(t)
	if env.ResourceAURL() == "" {
		t.Skip("resource servers not available")
	}

	clientID, clientSecret := RegisterApp(t, env, "fed-test.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	// Mint resource token
	token, err := admin.MintResourceToken("fed-user@example.com", clientID, clientSecret,
		admin.AppQuota{MaxRooms: 10}, []string{"collab"})
	require.NoError(t, err)

	// Validate against resource server A
	req, _ := http.NewRequest("POST", env.ResourceAURL()+"/validate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := env.AuthServer.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode, "resource server should accept valid token")
	data := ReadJSON(resp)
	assert.Equal(t, "fed-user@example.com", data["user_id"])
	assert.True(t, data["valid"].(bool))
}

// TestFederated_WrongSecretRejected verifies that a token signed with the
// wrong secret is rejected by the resource server.
func TestFederated_WrongSecretRejected(t *testing.T) {
	env := NewTestEnv(t)
	if env.ResourceAURL() == "" {
		t.Skip("resource servers not available")
	}

	clientID, _ := RegisterApp(t, env, "wrong-secret.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	// Mint with wrong secret
	token, err := admin.MintResourceToken("hacker@evil.com", clientID, "wrong-secret",
		admin.AppQuota{}, []string{"read"})
	require.NoError(t, err)

	req, _ := http.NewRequest("POST", env.ResourceAURL()+"/validate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := env.AuthServer.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 401, resp.StatusCode, "wrong-secret token should be rejected")
}

// TestFederated_CrossResourceServer verifies that the same token works
// on both resource servers (they both use JWKS from the same auth server).
func TestFederated_CrossResourceServer(t *testing.T) {
	env := NewTestEnv(t)
	if env.ResourceAURL() == "" || env.ResourceBURL() == "" {
		t.Skip("resource servers not available")
	}

	clientID, clientSecret := RegisterApp(t, env, "cross-rs.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	token, err := admin.MintResourceToken("user@example.com", clientID, clientSecret,
		admin.AppQuota{}, []string{"read"})
	require.NoError(t, err)

	for _, rsURL := range []string{env.ResourceAURL(), env.ResourceBURL()} {
		req, _ := http.NewRequest("POST", rsURL+"/validate", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := env.AuthServer.Client().Do(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode, "token should work on %s", rsURL)
		resp.Body.Close()
	}
}

// TestFederated_DeletedAppTokenRejected verifies that after deleting an app,
// its tokens are rejected by the resource server (key removed from KeyStore).
func TestFederated_DeletedAppTokenRejected(t *testing.T) {
	env := NewTestEnv(t)
	if env.ResourceAURL() == "" {
		t.Skip("resource servers not available")
	}

	clientID, clientSecret := RegisterApp(t, env, "delete-fed.example.com")

	token, err := admin.MintResourceToken("user@example.com", clientID, clientSecret,
		admin.AppQuota{}, []string{"read"})
	require.NoError(t, err)

	// Delete the app
	NewTestClient(env).Delete("/apps/" + clientID)

	// Force JWKS refresh on resource server (cache may still have old keys)
	// In-process, the JWKSKeyStore does a refresh on cache miss
	req, _ := http.NewRequest("POST", env.ResourceAURL()+"/validate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := env.AuthServer.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Token should fail — key was deleted from KeyStore
	assert.Equal(t, 401, resp.StatusCode, "deleted app's token should be rejected")
}
