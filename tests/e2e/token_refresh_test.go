package e2e_test

// Token refresh lifecycle — password grant, refresh, rotation, reuse detection, logout.
//
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-10.4

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRefresh_PasswordGrant(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "refresh")
	c := NewTestClient(env)

	resp := c.PostJSON("/api/token", map[string]any{
		"grant_type": "password",
		"username":   email,
		"password":   password,
	})
	require.Equal(t, 200, resp.StatusCode)
	data := ReadJSON(resp)
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
}

func TestTokenRefresh_RefreshGrant(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "refresh2")
	access, refresh := LoginForTokens(t, env, email, password)
	c := NewTestClient(env)

	resp := c.PostJSON("/api/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
	})
	require.Equal(t, 200, resp.StatusCode)
	data := ReadJSON(resp)
	assert.NotEqual(t, access, data["access_token"])
	assert.NotEqual(t, refresh, data["refresh_token"])
}

// TestTokenRefresh_OldRefreshTokenRejected verifies that after rotation,
// the old refresh token is rejected (it's been revoked during rotation).
func TestTokenRefresh_OldRefreshTokenRejected(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "refresh3")
	_, oldRefresh := LoginForTokens(t, env, email, password)
	c := NewTestClient(env)

	// Rotate
	resp := c.PostJSON("/api/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": oldRefresh,
	})
	require.Equal(t, 200, resp.StatusCode)

	// Old token should be rejected
	resp = c.PostJSON("/api/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": oldRefresh,
	})
	assert.Equal(t, 401, resp.StatusCode)
}

// TestTokenRefresh_ReuseRevokesFamily verifies that reusing an old refresh
// token (after it was rotated) triggers family-wide revocation — even the
// new token becomes invalid. This is the theft detection mechanism.
//
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-10.4
func TestTokenRefresh_ReuseRevokesFamily(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "refresh-reuse")
	_, oldRefresh := LoginForTokens(t, env, email, password)
	c := NewTestClient(env)

	// Rotate to get new token
	resp := c.PostJSON("/api/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": oldRefresh,
	})
	require.Equal(t, 200, resp.StatusCode)
	newRefresh := ReadJSON(resp)["refresh_token"].(string)

	// Attacker reuses old token → triggers family revocation
	resp = c.PostJSON("/api/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": oldRefresh,
	})
	assert.Equal(t, 401, resp.StatusCode)

	// New token should ALSO be revoked (family compromise)
	resp = c.PostJSON("/api/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": newRefresh,
	})
	assert.Equal(t, 401, resp.StatusCode,
		"new refresh token should be revoked after family compromise")
}

func TestTokenRefresh_Logout(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "refresh-logout")
	_, refresh := LoginForTokens(t, env, email, password)
	c := NewTestClient(env)

	resp := c.PostJSON("/api/logout", map[string]any{
		"refresh_token": refresh,
	})
	assert.Equal(t, 204, resp.StatusCode)

	// Refresh should now fail
	resp = c.PostJSON("/api/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
	})
	assert.Equal(t, 401, resp.StatusCode)
}
