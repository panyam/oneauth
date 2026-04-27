package apiauth_test

// Tests for the Token Revocation endpoint (RFC 7009).
// The revocation endpoint allows clients to notify the AS that a token
// is no longer needed. The AS blacklists access tokens (jti-based) and
// revokes refresh tokens.
//
// Key RFC 7009 requirements tested:
//   - Always returns 200 OK (even for invalid tokens)
//   - Never reveals whether the token existed
//   - Requires client authentication
//   - Supports token_type_hint
//
// See: https://www.rfc-editor.org/rfc/rfc7009

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRevocation creates a RevocationHandler with an APIAuth that can
// mint tokens, a blacklist for access token revocation, and a refresh
// token store.
func setupRevocation(t *testing.T) (*apiauth.RevocationHandler, *apiauth.APIAuth, *apiauth.IntrospectionHandler) {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	ks.PutKey(&keys.KeyRecord{
		ClientID:  "revoke-client",
		Key:       []byte("revoke-client-secret"),
		Algorithm: "HS256",
	})

	blacklist := core.NewInMemoryBlacklist()
	refreshStore := newInMemoryRefreshStore()

	auth := &apiauth.APIAuth{
		JWTSecretKey:      "revocation-test-secret-32chars-m!",
		JWTIssuer:         "test-issuer",
		Blacklist:         blacklist,
		RefreshTokenStore: refreshStore,
		ClientKeyStore:    ks,
	}

	revHandler := apiauth.NewRevocationHandler(auth, ks)

	introHandler := apiauth.NewIntrospectionHandler(auth, ks)

	return revHandler, auth, introHandler
}

// postRevoke sends a form-encoded POST to the revocation handler.
func postRevoke(t *testing.T, handler http.Handler, token, hint, clientID, clientSecret string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// TestRevocation_AccessToken verifies that revoking an access token causes
// subsequent introspection to return active: false.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2
func TestRevocation_AccessToken(t *testing.T) {
	revHandler, auth, introHandler := setupRevocation(t)

	// Mint an access token
	token, _, err := auth.CreateAccessToken("user-1", []string{"read"}, nil)
	require.NoError(t, err)

	// Verify it's active via introspection
	rr := postIntrospect(t, introHandler, token, "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"active":true`)

	// Revoke it
	rr = postRevoke(t, revHandler, token, "access_token", "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)

	// Introspect again — should be inactive
	rr = postIntrospect(t, introHandler, token, "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"active":false`)
}

// TestRevocation_RefreshToken verifies that revoking a refresh token makes
// it unusable for token refresh.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2
func TestRevocation_RefreshToken(t *testing.T) {
	revHandler, auth, _ := setupRevocation(t)

	// Create a refresh token
	rt, err := auth.RefreshTokenStore.CreateRefreshToken("user-1", "revoke-client", nil, []string{"read"})
	require.NoError(t, err)

	// Revoke it
	rr := postRevoke(t, revHandler, rt.Token, "refresh_token", "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)

	// Try to get the refresh token — should be revoked
	got, err := auth.RefreshTokenStore.GetRefreshToken(rt.Token)
	require.NoError(t, err)
	assert.True(t, got.Revoked, "refresh token should be revoked")
}

// TestRevocation_NoHint verifies that without a token_type_hint, the handler
// tries refresh token first, then access token.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestRevocation_NoHint(t *testing.T) {
	revHandler, auth, introHandler := setupRevocation(t)

	// Mint an access token and revoke with no hint
	token, _, err := auth.CreateAccessToken("user-2", []string{"write"}, nil)
	require.NoError(t, err)

	rr := postRevoke(t, revHandler, token, "", "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)

	// Should be revoked (handler tried refresh first, failed, then tried access token)
	rr = postIntrospect(t, introHandler, token, "revoke-client", "revoke-client-secret")
	assert.Contains(t, rr.Body.String(), `"active":false`)
}

// TestRevocation_AlreadyRevoked verifies that revoking an already-revoked
// token still returns 200 OK per RFC 7009 §2.2.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.2
func TestRevocation_AlreadyRevoked(t *testing.T) {
	revHandler, auth, _ := setupRevocation(t)

	token, _, _ := auth.CreateAccessToken("user-3", []string{"read"}, nil)

	// Revoke twice — both should succeed
	rr := postRevoke(t, revHandler, token, "access_token", "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)

	rr = postRevoke(t, revHandler, token, "access_token", "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestRevocation_GarbageToken verifies that submitting an invalid token
// returns 200 OK — the AS never reveals whether the token existed.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.2
func TestRevocation_GarbageToken(t *testing.T) {
	revHandler, _, _ := setupRevocation(t)

	rr := postRevoke(t, revHandler, "not-a-real-token", "", "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestRevocation_EmptyToken verifies that submitting an empty token
// returns 200 OK.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestRevocation_EmptyToken(t *testing.T) {
	revHandler, _, _ := setupRevocation(t)

	rr := postRevoke(t, revHandler, "", "", "revoke-client", "revoke-client-secret")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestRevocation_NoAuth verifies that an unauthenticated request is rejected
// with 401 Unauthorized.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestRevocation_NoAuth(t *testing.T) {
	revHandler, _, _ := setupRevocation(t)

	rr := postRevoke(t, revHandler, "some-token", "", "", "")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestRevocation_BadAuth verifies that invalid credentials are rejected.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestRevocation_BadAuth(t *testing.T) {
	revHandler, _, _ := setupRevocation(t)

	rr := postRevoke(t, revHandler, "some-token", "", "revoke-client", "wrong-secret")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestRevocation_MethodNotAllowed verifies that GET is rejected with 405.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2
func TestRevocation_MethodNotAllowed(t *testing.T) {
	revHandler, _, _ := setupRevocation(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/revoke", nil)
	rr := httptest.NewRecorder()
	revHandler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// --- In-memory refresh token store for tests ---

type inMemoryRefreshStore struct {
	tokens map[string]*core.RefreshToken
}

func newInMemoryRefreshStore() *inMemoryRefreshStore {
	return &inMemoryRefreshStore{tokens: make(map[string]*core.RefreshToken)}
}

func (s *inMemoryRefreshStore) CreateRefreshToken(userID, clientID string, deviceInfo map[string]any, scopes []string) (*core.RefreshToken, error) {
	token, _ := core.GenerateSecureToken()
	rt := &core.RefreshToken{
		Token:    token,
		UserID:   userID,
		ClientID: clientID,
		Scopes:   scopes,
	}
	s.tokens[token] = rt
	return rt, nil
}

func (s *inMemoryRefreshStore) GetRefreshToken(token string) (*core.RefreshToken, error) {
	rt, ok := s.tokens[token]
	if !ok {
		return nil, core.ErrTokenNotFound
	}
	return rt, nil
}

func (s *inMemoryRefreshStore) RevokeRefreshToken(token string) error {
	rt, ok := s.tokens[token]
	if !ok {
		return nil // don't reveal
	}
	rt.Revoked = true
	return nil
}

func (s *inMemoryRefreshStore) RotateRefreshToken(old string) (*core.RefreshToken, error) {
	return nil, core.ErrTokenNotFound
}

func (s *inMemoryRefreshStore) RevokeUserTokens(userID string) error { return nil }
func (s *inMemoryRefreshStore) RevokeTokenFamily(family string) error { return nil }
func (s *inMemoryRefreshStore) GetUserTokens(userID string) ([]*core.RefreshToken, error) {
	return nil, nil
}
func (s *inMemoryRefreshStore) CleanupExpiredTokens() error { return nil }
