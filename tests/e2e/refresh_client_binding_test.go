package e2e_test

// The refresh grant checks that a refresh token belongs to the client
// presenting it (RFC 6749 §6). These run the SDK against the real token
// endpoint, so a client that refreshes under a different client_id than it
// logged in with shows up here rather than in production.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
// See: https://www.rfc-editor.org/rfc/rfc6749#section-10.4

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
)

// The SDK's automatic refresh must present the client the credential was
// issued to. It used to send "cli" regardless, which the AS now refuses for
// a token issued to any other client.
func TestRefreshClientBinding_SDKAutoRefreshKeepsItsClientID(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "refresh-binding")
	store := &memCredentialStore{creds: make(map[string]*client.ServerCredential)}
	c := client.NewAuthClient(env.BaseURL(), store, client.WithTokenEndpoint("/api/token"))

	cred, err := c.Login(context.Background(), &client.LoginRequest{
		Username: email, Password: password, ClientID: "my-cli-app",
	})
	require.NoError(t, err)
	require.NotEmpty(t, cred.RefreshToken)
	assert.Equal(t, "my-cli-app", cred.ClientID)

	cred.ExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, store.SetCredential(env.BaseURL(), cred))

	token, err := c.GetToken()
	require.NoError(t, err)
	require.NotEmpty(t, token, "auto-refresh must succeed for a token issued to my-cli-app")
	assert.NotEqual(t, cred.AccessToken, token)

	refreshed, err := store.GetCredential(env.BaseURL())
	require.NoError(t, err)
	assert.NotEqual(t, cred.RefreshToken, refreshed.RefreshToken, "the AS rotates on refresh")
	assert.Equal(t, "my-cli-app", refreshed.ClientID, "the client stays with the credential across refreshes")
}

// A refresh token from the password grant run with a client_id can't be
// redeemed without one, or under another client's.
func TestRefreshClientBinding_RawRequestsWithTheWrongClient(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "refresh-binding-raw")
	c := NewTestClient(env)

	resp := c.PostJSON("/api/token", map[string]any{
		"grant_type": "password", "username": email, "password": password, "client_id": "my-cli-app",
	})
	require.Equal(t, 200, resp.StatusCode)
	refresh, _ := ReadJSON(resp)["refresh_token"].(string)
	require.NotEmpty(t, refresh)

	for name, body := range map[string]map[string]any{
		"no client_id":    {"grant_type": "refresh_token", "refresh_token": refresh},
		"other client_id": {"grant_type": "refresh_token", "refresh_token": refresh, "client_id": "someone-else"},
	} {
		resp := c.PostJSON("/api/token", body)
		data := ReadJSON(resp)
		assert.Equal(t, "invalid_grant", data["error"], name)
		assert.Nil(t, data["access_token"], name)
	}

	resp = c.PostJSON("/api/token", map[string]any{
		"grant_type": "refresh_token", "refresh_token": refresh, "client_id": "my-cli-app",
	})
	require.Equal(t, 200, resp.StatusCode, "the refused attempts must not have burned the owner's token")
}
