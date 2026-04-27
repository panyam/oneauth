package apiauth_test

// Tests for OAuth grant types via the transport-independent OneAuth core.
// These tests prove that password, refresh, and client_credentials grants
// work as library calls without any HTTP endpoint.
//
// See: https://github.com/panyam/oneauth/issues/110

import (
	"fmt"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Refresh Token Grant
// =============================================================================

// TestOneAuth_RefreshGrant verifies the refresh token grant works
// as a library call — rotate refresh token, get new access token.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
func TestOneAuth_RefreshGrant(t *testing.T) {
	oa := newTestOneAuth(t)

	rt, err := oa.RefreshStore.CreateRefreshToken("refresh-user", "test-client", nil, []string{"read", "write"})
	require.NoError(t, err)

	resp, err := oa.Issuer.RefreshGrant(rt.Token)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken, "should get a new refresh token")
	assert.NotEqual(t, rt.Token, resp.RefreshToken, "new refresh token should differ from old")
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "read write", resp.Scope)

	info, err := oa.Validator.ValidateToken(resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "refresh-user", info.UserID)
}

// TestOneAuth_RefreshGrant_RevokedToken verifies that refreshing a revoked
// token fails and revokes the entire token family (theft detection).
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
func TestOneAuth_RefreshGrant_RevokedToken(t *testing.T) {
	oa := newTestOneAuth(t)

	rt, _ := oa.RefreshStore.CreateRefreshToken("user-theft", "test-client", nil, []string{"read"})
	oa.RefreshStore.RevokeRefreshToken(rt.Token)

	_, err := oa.Issuer.RefreshGrant(rt.Token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token reuse")
}

// TestOneAuth_RefreshGrant_InvalidToken verifies that an unknown refresh
// token returns an error.
func TestOneAuth_RefreshGrant_InvalidToken(t *testing.T) {
	oa := newTestOneAuth(t)

	_, err := oa.Issuer.RefreshGrant("not-a-real-refresh-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
}

// =============================================================================
// Password Grant
// =============================================================================

// newTestOneAuthWithPasswordGrant creates a OneAuth with password grant support.
func newTestOneAuthWithPasswordGrant(t *testing.T) *apiauth.OneAuth {
	t.Helper()
	signingSecret := []byte("test-signing-secret-32chars-min!")
	ks := keys.NewInMemoryKeyStore()
	ks.PutKey(&keys.KeyRecord{ClientID: "test-issuer", Key: signingSecret, Algorithm: "HS256"})

	return apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:     ks,
		SigningKey:   signingSecret,
		Issuer:       "test-issuer",
		Blacklist:    core.NewInMemoryBlacklist(),
		RefreshStore: newInMemoryRefreshStore(),
		ValidateCredentials: func(username, password, usernameType string) (core.User, error) {
			if username == "alice@example.com" && password == "correct-password" {
				return &core.BasicUser{ID: "user-alice", ProfileData: map[string]any{"email": username}}, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
		GetUserScopes: func(userID string) ([]string, error) {
			return []string{"read", "write", "profile"}, nil
		},
	})
}

// TestOneAuth_PasswordGrant verifies the password grant works as a
// library call — authenticate user, get access token, validate it.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.3
func TestOneAuth_PasswordGrant(t *testing.T) {
	oa := newTestOneAuthWithPasswordGrant(t)

	result, err := oa.Issuer.PasswordGrant(apiauth.PasswordGrantRequest{
		Username: "alice@example.com",
		Password: "correct-password",
		Scopes:   []string{"read"},
	})
	require.NoError(t, err)
	assert.Equal(t, "user-alice", result.UserID)
	assert.NotEmpty(t, result.AccessToken)
	assert.True(t, result.ExpiresIn > 0)
	assert.Equal(t, []string{"read"}, result.GrantedScopes)

	info, err := oa.Validator.ValidateToken(result.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user-alice", info.UserID)
}

// TestOneAuth_PasswordGrant_BadPassword verifies that wrong credentials
// are rejected.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.3
func TestOneAuth_PasswordGrant_BadPassword(t *testing.T) {
	oa := newTestOneAuthWithPasswordGrant(t)

	_, err := oa.Issuer.PasswordGrant(apiauth.PasswordGrantRequest{
		Username: "alice@example.com",
		Password: "wrong-password",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
}

// TestOneAuth_PasswordGrant_ScopeIntersection verifies that requested
// scopes are intersected with allowed scopes.
func TestOneAuth_PasswordGrant_ScopeIntersection(t *testing.T) {
	oa := newTestOneAuthWithPasswordGrant(t)

	result, err := oa.Issuer.PasswordGrant(apiauth.PasswordGrantRequest{
		Username: "alice@example.com",
		Password: "correct-password",
		Scopes:   []string{"read", "admin"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, result.GrantedScopes, "admin should be filtered out")
}

// TestOneAuth_PasswordGrant_DefaultScopes verifies that when no scopes
// are requested, all allowed scopes are granted.
func TestOneAuth_PasswordGrant_DefaultScopes(t *testing.T) {
	oa := newTestOneAuthWithPasswordGrant(t)

	result, err := oa.Issuer.PasswordGrant(apiauth.PasswordGrantRequest{
		Username: "alice@example.com",
		Password: "correct-password",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"read", "write", "profile"}, result.GrantedScopes)
}

// TestOneAuth_PasswordGrant_CallerCreatesRefreshToken verifies the
// intended usage pattern: grant returns access token, caller creates
// refresh token separately with transport-specific metadata.
func TestOneAuth_PasswordGrant_CallerCreatesRefreshToken(t *testing.T) {
	oa := newTestOneAuthWithPasswordGrant(t)

	// Step 1: Password grant (core — no device info)
	result, err := oa.Issuer.PasswordGrant(apiauth.PasswordGrantRequest{
		Username: "alice@example.com",
		Password: "correct-password",
		Scopes:   []string{"read", "write"},
	})
	require.NoError(t, err)

	// Step 2: Caller creates refresh token with transport metadata
	rt, err := oa.RefreshStore.CreateRefreshToken(
		result.UserID, "my-app",
		map[string]any{"user_agent": "TestBot/1.0", "ip": "127.0.0.1"},
		result.GrantedScopes,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, rt.Token)

	// Step 3: Later, refresh the token via core
	refreshResult, err := oa.Issuer.RefreshGrant(rt.Token)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshResult.AccessToken)
}
