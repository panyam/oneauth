package client

// Tests for nil CredentialStore safety (#76).
//
// NewAuthClient(url, nil) must not panic — all methods should work correctly
// with a nil store by substituting a no-op store (null object pattern).
// These tests cover every code path that dereferences c.store.
//
// See: https://github.com/panyam/oneauth/issues/76

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthClient_NilStore_GetToken verifies that NewAuthClient(url, nil) does
// not panic when calling GetToken. Before the fix for #76, this panicked with
// a nil pointer dereference on c.store.GetCredential. With the no-op store,
// GetToken returns an empty string (no credential stored).
//
// See: https://github.com/panyam/oneauth/issues/76
func TestAuthClient_NilStore_GetToken(t *testing.T) {
	c := NewAuthClient("http://localhost:8080", nil)
	token, err := c.GetToken()
	assert.NoError(t, err)
	assert.Empty(t, token)
}

// TestAuthClient_NilStore_IsLoggedIn verifies that IsLoggedIn returns false
// (not panic) when the credential store is nil. A nil store means "no
// persistence" — no credentials are ever stored, so the client is never
// logged in.
//
// See: https://github.com/panyam/oneauth/issues/76
func TestAuthClient_NilStore_IsLoggedIn(t *testing.T) {
	c := NewAuthClient("http://localhost:8080", nil)
	assert.False(t, c.IsLoggedIn())
}

// TestAuthClient_NilStore_GetCredential verifies that GetCredential returns
// nil (not panic) when the credential store is nil.
//
// See: https://github.com/panyam/oneauth/issues/76
func TestAuthClient_NilStore_GetCredential(t *testing.T) {
	c := NewAuthClient("http://localhost:8080", nil)
	cred, err := c.GetCredential()
	assert.NoError(t, err)
	assert.Nil(t, cred)
}

// TestAuthClient_NilStore_Logout verifies that Logout does not panic when the
// credential store is nil. The no-op store silently discards the remove request.
//
// See: https://github.com/panyam/oneauth/issues/76
func TestAuthClient_NilStore_Logout(t *testing.T) {
	c := NewAuthClient("http://localhost:8080", nil)
	err := c.Logout()
	assert.NoError(t, err)
}

// TestAuthClient_NilStore_Login verifies that Login completes the token
// request without panicking when the credential store is nil. The token is
// obtained from the server and returned to the caller, but silently discarded
// by the no-op store (not persisted between calls).
//
// See: https://github.com/panyam/oneauth/issues/76
func TestAuthClient_NilStore_Login(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken: "test-token",
			TokenType:   "bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	c := NewAuthClient(server.URL, nil)
	cred, err := c.Login("user", "pass", "")
	require.NoError(t, err)
	assert.Equal(t, "test-token", cred.AccessToken)

	// Verify the token is NOT persisted (no-op store returns nil)
	stored, err := c.GetCredential()
	assert.NoError(t, err)
	assert.Nil(t, stored, "no-op store should not persist credentials")
}

// TestAuthClient_NilStore_ClientCredentialsToken verifies that
// ClientCredentialsToken works with a nil store — the token is returned but
// not persisted.
//
// See: https://github.com/panyam/oneauth/issues/76
func TestAuthClient_NilStore_ClientCredentialsToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken: "cc-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	c := NewAuthClient(server.URL, nil, WithTokenEndpoint("/token"))
	cred, err := c.ClientCredentialsToken("my-client", "my-secret", nil)
	require.NoError(t, err)
	assert.Equal(t, "cc-token", cred.AccessToken)
}

// TestAuthClient_NilStore_LoginWithBrowser verifies that LoginWithBrowser does
// not panic when the AuthClient was created with a nil CredentialStore. The
// credential is returned to the caller but silently discarded by the no-op store.
// This is the primary scenario from issue #76 — MCPKit's OAuthTokenSource creates
// AuthClient without a credential store for conformance testing.
//
// See: https://github.com/panyam/oneauth/issues/76
func TestAuthClient_NilStore_LoginWithBrowser(t *testing.T) {
	authSrv := mockAuthServer(t)

	c := NewAuthClient(authSrv.URL, nil)
	cred, err := c.LoginWithBrowser(BrowserLoginConfig{
		ClientID:    "test-cli",
		Scopes:      []string{"openid"},
		Timeout:     10 * time.Second,
		OpenBrowser: FollowRedirects(nil),
	})

	require.NoError(t, err)
	assert.Equal(t, "mock-access-token", cred.AccessToken)
	assert.Equal(t, "mock-refresh-token", cred.RefreshToken)
}
