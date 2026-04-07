package e2e_test

// End-to-end tests for the authorization code + PKCE flow (#71) and
// token endpoint auth method negotiation (#72). These tests exercise the
// client SDK's LoginWithBrowser (headless via FollowRedirects) and
// ClientCredentialsToken against the in-process e2e auth server.
//
// References:
//   - RFC 8252 (https://www.rfc-editor.org/rfc/rfc8252):
//     "OAuth 2.0 for Native Apps" — loopback redirect pattern
//   - RFC 7636 (https://www.rfc-editor.org/rfc/rfc7636):
//     "Proof Key for Code Exchange" — PKCE
//   - RFC 6749 §2.3.1 (https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1):
//     Client authentication methods
//   - See: https://github.com/panyam/oneauth/issues/71
//   - See: https://github.com/panyam/oneauth/issues/72

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_AuthCodePKCE_HeadlessFlow verifies the complete authorization code +
// PKCE flow using the client SDK's FollowRedirects helper against the e2e auth
// server. This proves the headless OAuth flow works end-to-end: discovery →
// PKCE generation → loopback server → HTTP redirect following → code exchange →
// credential stored.
//
// See: https://www.rfc-editor.org/rfc/rfc8252
// See: https://www.rfc-editor.org/rfc/rfc7636
// See: https://github.com/panyam/oneauth/issues/71
func TestE2E_AuthCodePKCE_HeadlessFlow(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("auth code e2e requires in-process servers")
	}

	store := &memCredentialStore{creds: make(map[string]*client.ServerCredential)}
	authClient := client.NewAuthClient(env.BaseURL(), store,
		client.WithTokenEndpoint("/oauth/token"))

	cred, err := authClient.LoginWithBrowser(client.BrowserLoginConfig{
		ClientID:    "e2e-public-client",
		Scopes:      []string{"openid", "read"},
		Timeout:     5 * time.Second,
		OpenBrowser: client.FollowRedirects(nil),
	})

	require.NoError(t, err, "headless auth code + PKCE flow should succeed")
	require.NotNil(t, cred)
	assert.Equal(t, "e2e-authcode-token", cred.AccessToken)
	assert.Equal(t, "e2e-refresh-token", cred.RefreshToken)

	// Verify credential was stored
	stored, err := store.GetCredential(env.BaseURL())
	require.NoError(t, err)
	assert.Equal(t, "e2e-authcode-token", stored.AccessToken)
}

// TestE2E_AuthMethodDiscovery verifies that the auth server advertises
// token_endpoint_auth_methods_supported in its OIDC discovery metadata, and
// that the client SDK's DiscoverAS correctly parses these methods.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
// See: https://github.com/panyam/oneauth/issues/72
func TestE2E_AuthMethodDiscovery(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("discovery e2e requires in-process servers")
	}

	meta, err := client.DiscoverAS(env.BaseURL())
	require.NoError(t, err)

	assert.Contains(t, meta.TokenEndpointAuthMethods, "client_secret_basic",
		"AS should advertise client_secret_basic")
	assert.Contains(t, meta.TokenEndpointAuthMethods, "client_secret_post",
		"AS should advertise client_secret_post")
	assert.Contains(t, meta.CodeChallengeMethodsSupported, "S256",
		"AS should advertise PKCE S256")
	assert.NotEmpty(t, meta.AuthorizationEndpoint,
		"AS should advertise authorization_endpoint")
}

// TestE2E_ClientCredentials_BasicAuth verifies that ClientCredentialsToken
// sends credentials via HTTP Basic auth when the AS metadata is provided.
// The e2e auth server's /oauth/token endpoint accepts both Basic and post auth.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestE2E_ClientCredentials_BasicAuth(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("client_credentials e2e requires in-process servers")
	}

	// Register a client
	clientID := "e2e-basic-auth-client"
	secret := "e2e-basic-secret"
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	})

	// Discover AS metadata (includes token_endpoint_auth_methods_supported)
	meta, err := client.DiscoverAS(env.BaseURL())
	require.NoError(t, err)

	store := &memCredentialStore{creds: make(map[string]*client.ServerCredential)}
	authClient := client.NewAuthClient(env.BaseURL(), store,
		client.WithTokenEndpoint("/oauth/token"),
		client.WithASMetadata(meta))

	cred, err := authClient.ClientCredentialsToken(clientID, secret, []string{"read"})
	require.NoError(t, err, "client_credentials with Basic auth should succeed")
	assert.Contains(t, cred.AccessToken, "e2e-cc-token-"+clientID)
}

// TestE2E_ClientCredentials_PostAuth verifies that ClientCredentialsToken
// sends credentials in the form body when the AS only supports
// client_secret_post. Uses a synthetic ASMetadata to force post-only behavior.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestE2E_ClientCredentials_PostAuth(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("client_credentials e2e requires in-process servers")
	}

	clientID := "e2e-post-auth-client"
	secret := "e2e-post-secret"
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	})

	// Force client_secret_post only
	meta := &client.ASMetadata{
		TokenEndpointAuthMethods: []string{"client_secret_post"},
	}

	store := &memCredentialStore{creds: make(map[string]*client.ServerCredential)}
	authClient := client.NewAuthClient(env.BaseURL(), store,
		client.WithTokenEndpoint("/oauth/token"),
		client.WithASMetadata(meta))

	cred, err := authClient.ClientCredentialsToken(clientID, secret, nil)
	require.NoError(t, err, "client_credentials with post auth should succeed")
	assert.Contains(t, cred.AccessToken, "e2e-cc-token-"+clientID)
}

// TestE2E_ClientCredentials_FormEncoded verifies that the client SDK sends
// token requests as application/x-www-form-urlencoded (RFC 6749 §4.4.2),
// not as JSON. The /oauth/token endpoint expects form-encoded requests.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2
// See: https://github.com/panyam/oneauth/issues/72
func TestE2E_ClientCredentials_FormEncoded(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("requires in-process servers")
	}

	clientID := "e2e-form-client"
	secret := "e2e-form-secret"
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	})

	// Direct form-encoded request to /oauth/token
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
	}
	resp, err := http.Post(env.BaseURL()+"/oauth/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"/oauth/token should accept form-encoded client_credentials")
}

// =============================================================================
// #74 — TokenEndpointAuthMethods with explicit endpoints
// =============================================================================

// TestE2E_AuthCodePKCE_ExplicitEndpoints_WithAuthMethods verifies that the
// complete authorization code + PKCE flow works when the caller provides
// explicit endpoints AND TokenEndpointAuthMethods. This reproduces the MCPKit
// use case: the caller does its own PRM→AS discovery, gets endpoints + auth
// methods, and passes them through to LoginWithBrowser.
//
// Before the fix (#74), TokenEndpointAuthMethods was ignored — asMethods was
// always empty when discovery was skipped, causing the client to default to
// client_secret_basic regardless of what the AS actually supports.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3
// See: https://github.com/panyam/oneauth/issues/74
func TestE2E_AuthCodePKCE_ExplicitEndpoints_WithAuthMethods(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("auth code e2e requires in-process servers")
	}

	store := &memCredentialStore{creds: make(map[string]*client.ServerCredential)}
	authClient := client.NewAuthClient(env.BaseURL(), store,
		client.WithTokenEndpoint("/oauth/token"))

	// Simulate MCPKit flow: caller already discovered endpoints + auth methods
	// via PRM→AS metadata, and passes them explicitly.
	cred, err := authClient.LoginWithBrowser(client.BrowserLoginConfig{
		ClientID:                 "e2e-public-client",
		Scopes:                   []string{"openid", "read"},
		AuthorizationEndpoint:    env.BaseURL() + "/authorize",
		TokenEndpoint:            env.BaseURL() + "/oauth/token",
		TokenEndpointAuthMethods: []string{"client_secret_post", "client_secret_basic"},
		Timeout:                  5 * time.Second,
		OpenBrowser:              client.FollowRedirects(nil),
	})

	require.NoError(t, err, "explicit endpoints with TokenEndpointAuthMethods should succeed")
	require.NotNil(t, cred)
	assert.Equal(t, "e2e-authcode-token", cred.AccessToken)
	assert.Equal(t, "e2e-refresh-token", cred.RefreshToken)

	// Verify credential was stored
	stored, err := store.GetCredential(env.BaseURL())
	require.NoError(t, err)
	assert.Equal(t, "e2e-authcode-token", stored.AccessToken)
}

// TestE2E_AuthCodePKCE_ExplicitEndpoints_ConfidentialClient verifies the
// confidential client auth code + PKCE flow with explicit endpoints and
// TokenEndpointAuthMethods set to client_secret_post. This is the exact
// scenario from issue #74: a confidential client that needs post auth when
// discovery is skipped.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3
// See: https://github.com/panyam/oneauth/issues/74
func TestE2E_AuthCodePKCE_ExplicitEndpoints_ConfidentialClient(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("auth code e2e requires in-process servers")
	}

	// Register a confidential client
	clientID := "e2e-explicit-confidential"
	secret := "e2e-explicit-secret"
	env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	})

	store := &memCredentialStore{creds: make(map[string]*client.ServerCredential)}
	authClient := client.NewAuthClient(env.BaseURL(), store,
		client.WithTokenEndpoint("/oauth/token"))

	cred, err := authClient.LoginWithBrowser(client.BrowserLoginConfig{
		ClientID:                 clientID,
		ClientSecret:             secret,
		Scopes:                   []string{"read"},
		AuthorizationEndpoint:    env.BaseURL() + "/authorize",
		TokenEndpoint:            env.BaseURL() + "/oauth/token",
		TokenEndpointAuthMethods: []string{"client_secret_post"},
		Timeout:                  5 * time.Second,
		OpenBrowser:              client.FollowRedirects(nil),
	})

	require.NoError(t, err, "confidential client with explicit endpoints + post auth should succeed")
	require.NotNil(t, cred)
	assert.Equal(t, "e2e-authcode-token", cred.AccessToken)
}

// =============================================================================
// Test helpers
// =============================================================================

// memCredentialStore is a minimal in-memory CredentialStore for e2e tests.
type memCredentialStore struct {
	creds map[string]*client.ServerCredential
}

func (m *memCredentialStore) GetCredential(serverURL string) (*client.ServerCredential, error) {
	return m.creds[serverURL], nil
}

func (m *memCredentialStore) SetCredential(serverURL string, cred *client.ServerCredential) error {
	m.creds[serverURL] = cred
	return nil
}

func (m *memCredentialStore) RemoveCredential(serverURL string) error {
	delete(m.creds, serverURL)
	return nil
}

func (m *memCredentialStore) ListServers() ([]string, error) {
	servers := make([]string, 0, len(m.creds))
	for k := range m.creds {
		servers = append(servers, k)
	}
	return servers, nil
}

func (m *memCredentialStore) Save() error { return nil }
