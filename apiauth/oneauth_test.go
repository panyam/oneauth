package apiauth_test

// Tests for the transport-independent OneAuth core.
// These tests prove that all auth operations work as library calls
// without any HTTP server, handler, or middleware.
//
// See: https://github.com/panyam/oneauth/issues/110

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

// newTestOneAuth creates a OneAuth instance for testing with in-memory stores.
func newTestOneAuth(t *testing.T) *apiauth.OneAuth {
	t.Helper()

	// The signing key is also stored in the KeyStore so the validator
	// can look it up by kid. The issuer field in KeyStore is the server's
	// own identity — tokens minted by CreateAccessToken get kid from this key.
	signingSecret := []byte("test-signing-secret-32chars-min!")

	ks := keys.NewInMemoryKeyStore()
	// Server's own signing key (for validating self-issued tokens)
	ks.PutKey(&keys.KeyRecord{
		ClientID:  "test-issuer",
		Key:       signingSecret,
		Algorithm: "HS256",
	})
	// A registered client (for client_credentials tests)
	ks.PutKey(&keys.KeyRecord{
		ClientID:  "test-client",
		Key:       []byte("test-client-secret-32chars-min!!"),
		Algorithm: "HS256",
	})

	return apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:     ks,
		SigningKey:    signingSecret,
		SigningAlg:    "HS256",
		Issuer:       "test-issuer",
		Blacklist:    core.NewInMemoryBlacklist(),
		RefreshStore: newInMemoryRefreshStore(),
	})
}

// TestOneAuth_CreateAccessToken verifies that tokens can be minted
// via the library without any HTTP endpoint.
//
// See: https://github.com/panyam/oneauth/issues/110
func TestOneAuth_CreateAccessToken(t *testing.T) {
	oa := newTestOneAuth(t)

	token, expiresIn, err := oa.Issuer.CreateAccessToken("alice", []string{"read", "write"}, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.True(t, expiresIn > 0)
}

// TestOneAuth_ValidateToken verifies that tokens can be validated
// via the library without any HTTP middleware.
//
// See: https://github.com/panyam/oneauth/issues/110
func TestOneAuth_ValidateToken(t *testing.T) {
	oa := newTestOneAuth(t)

	token, _, err := oa.Issuer.CreateAccessToken("bob", []string{"read"}, nil)
	require.NoError(t, err)

	info, err := oa.Validator.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "bob", info.UserID)
	assert.Equal(t, []string{"read"}, info.Scopes)
	assert.Equal(t, "jwt", info.AuthType)
}

// TestOneAuth_ValidateToken_WithRAR verifies that RFC 9396
// authorization_details are extracted from tokens via library calls.
//
// See: https://www.rfc-editor.org/rfc/rfc9396
func TestOneAuth_ValidateToken_WithRAR(t *testing.T) {
	oa := newTestOneAuth(t)

	details := []core.AuthorizationDetail{
		{Type: "payment_initiation", Actions: []string{"initiate"}},
	}
	token, _, err := oa.Issuer.CreateAccessToken("alice", []string{"payments"}, details)
	require.NoError(t, err)

	info, err := oa.Validator.ValidateToken(token)
	require.NoError(t, err)
	require.Len(t, info.AuthorizationDetails, 1)
	assert.Equal(t, "payment_initiation", info.AuthorizationDetails[0].Type)
}

// TestOneAuth_Introspect verifies that token introspection works
// via the library without any HTTP endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc7662
func TestOneAuth_Introspect(t *testing.T) {
	oa := newTestOneAuth(t)

	token, _, _ := oa.Issuer.CreateAccessToken("charlie", []string{"read"}, nil)

	result, err := oa.Introspector.Introspect(token)
	require.NoError(t, err)
	assert.True(t, result.Active)
	assert.Equal(t, "charlie", result.Sub)
	assert.Contains(t, result.Scope, "read")
}

// TestOneAuth_Introspect_Invalid verifies that introspecting a garbage
// token returns {Active: false} without an error.
//
// See: https://www.rfc-editor.org/rfc/rfc7662
func TestOneAuth_Introspect_Invalid(t *testing.T) {
	oa := newTestOneAuth(t)

	result, err := oa.Introspector.Introspect("garbage-token")
	require.NoError(t, err)
	assert.False(t, result.Active)
}

// TestOneAuth_Revoke_AccessToken verifies that revoking an access token
// makes it fail validation and introspection — all via library calls.
//
// See: https://www.rfc-editor.org/rfc/rfc7009
func TestOneAuth_Revoke_AccessToken(t *testing.T) {
	oa := newTestOneAuth(t)

	token, _, _ := oa.Issuer.CreateAccessToken("dave", []string{"read"}, nil)

	// Valid before revocation
	result, _ := oa.Introspector.Introspect(token)
	assert.True(t, result.Active)

	// Revoke
	err := oa.Revoker.Revoke(token, "access_token")
	require.NoError(t, err)

	// Invalid after revocation
	result, _ = oa.Introspector.Introspect(token)
	assert.False(t, result.Active)

	// Validation also fails
	_, err = oa.Validator.ValidateToken(token)
	assert.Error(t, err)
}

// TestOneAuth_Revoke_RefreshToken verifies that refresh token revocation
// works via the library.
//
// See: https://www.rfc-editor.org/rfc/rfc7009
func TestOneAuth_Revoke_RefreshToken(t *testing.T) {
	oa := newTestOneAuth(t)

	rt, err := oa.RefreshStore.CreateRefreshToken("eve", "test-client", nil, []string{"read"})
	require.NoError(t, err)

	err = oa.Revoker.Revoke(rt.Token, "refresh_token")
	require.NoError(t, err)

	got, _ := oa.RefreshStore.GetRefreshToken(rt.Token)
	assert.True(t, got.Revoked)
}

// TestOneAuth_ClientCredentials verifies the full client_credentials
// grant via library calls — no HTTP.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestOneAuth_ClientCredentials(t *testing.T) {
	oa := newTestOneAuth(t)

	resp, err := oa.Issuer.ClientCredentials(
		"test-client", "test-client-secret-32chars-min!!",
		[]string{"read", "write"}, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "read write", resp.Scope)

	// Token should be valid
	info, err := oa.Validator.ValidateToken(resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "test-client", info.UserID) // sub = client_id for CC
}

// TestOneAuth_ClientCredentials_BadSecret verifies that bad credentials
// are rejected.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func TestOneAuth_ClientCredentials_BadSecret(t *testing.T) {
	oa := newTestOneAuth(t)

	_, err := oa.Issuer.ClientCredentials("test-client", "wrong-secret", nil, nil)
	assert.Error(t, err)
}

// TestOneAuth_CheckScopes verifies scope enforcement via library calls.
func TestOneAuth_CheckScopes(t *testing.T) {
	oa := newTestOneAuth(t)

	token, _, _ := oa.Issuer.CreateAccessToken("frank", []string{"read"}, nil)

	assert.NoError(t, oa.Validator.CheckScopes(token, []string{"read"}))
	assert.Error(t, oa.Validator.CheckScopes(token, []string{"write"}))
	assert.Error(t, oa.Validator.CheckScopes(token, []string{"read", "write"}))
}

// TestOneAuth_CheckAuthorizationDetails verifies RAR enforcement via library calls.
//
// See: https://www.rfc-editor.org/rfc/rfc9396
func TestOneAuth_CheckAuthorizationDetails(t *testing.T) {
	oa := newTestOneAuth(t)

	details := []core.AuthorizationDetail{
		{Type: "payment_initiation", Actions: []string{"initiate"}},
	}
	token, _, _ := oa.Issuer.CreateAccessToken("grace", []string{"payments"}, details)

	assert.NoError(t, oa.Validator.CheckAuthorizationDetails(token, []string{"payment_initiation"}))
	assert.Error(t, oa.Validator.CheckAuthorizationDetails(token, []string{"account_information"}))
}

// TestOneAuth_Hooks_OnIssued verifies that the OnIssued hook fires
// when a token is created.
func TestOneAuth_Hooks_OnIssued(t *testing.T) {
	var firedSubject, firedGrant string
	secret := []byte("hooks-test-secret-32chars-min!!!")
	ks := keys.NewInMemoryKeyStore()
	ks.PutKey(&keys.KeyRecord{ClientID: "test", Key: secret, Algorithm: "HS256"})
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:   ks,
		SigningKey:  secret,
		Issuer:     "test",
		Blacklist:  core.NewInMemoryBlacklist(),
		Hooks: apiauth.Hooks{
			Token: apiauth.TokenHooks{
				OnIssued: func(subject, grantType string) {
					firedSubject = subject
					firedGrant = grantType
				},
			},
		},
	})

	oa.Issuer.CreateAccessToken("hook-user", []string{"read"}, nil)
	assert.Equal(t, "hook-user", firedSubject)
	assert.Equal(t, "direct", firedGrant)
}

// TestOneAuth_Hooks_OnRevoked verifies that the OnRevoked hook fires
// when a token is revoked.
func TestOneAuth_Hooks_OnRevoked(t *testing.T) {
	var firedHint string
	ks := keys.NewInMemoryKeyStore()
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:   ks,
		SigningKey:  []byte("hooks-test-secret-32chars-min!!!"),
		Issuer:     "test",
		Blacklist:  core.NewInMemoryBlacklist(),
		Hooks: apiauth.Hooks{
			Token: apiauth.TokenHooks{
				OnRevoked: func(token, hint string) {
					firedHint = hint
				},
			},
		},
	})

	token, _, _ := oa.Issuer.CreateAccessToken("user-1", []string{"read"}, nil)
	oa.Revoker.Revoke(token, "access_token")
	assert.Equal(t, "access_token", firedHint)
}

// TestOneAuth_Hooks_OnBlacklistHit verifies that the OnBlacklistHit hook
// fires when a revoked token is presented for validation.
func TestOneAuth_Hooks_OnBlacklistHit(t *testing.T) {
	var firedJTI string
	secret := []byte("hooks-test-secret-32chars-min!!!")
	ks := keys.NewInMemoryKeyStore()
	ks.PutKey(&keys.KeyRecord{ClientID: "test", Key: secret, Algorithm: "HS256"})
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:   ks,
		SigningKey:  secret,
		Issuer:     "test",
		Blacklist:  core.NewInMemoryBlacklist(),
		Hooks: apiauth.Hooks{
			Security: apiauth.SecurityHooks{
				OnBlacklistHit: func(jti string) {
					firedJTI = jti
				},
			},
		},
	})

	token, _, _ := oa.Issuer.CreateAccessToken("user-2", []string{"read"}, nil)
	oa.Revoker.Revoke(token, "access_token")

	// Try to validate the revoked token — should trigger blacklist hit hook
	_, err := oa.Validator.ValidateToken(token)
	assert.Error(t, err)
	assert.NotEmpty(t, firedJTI, "OnBlacklistHit should have fired")
}

// =============================================================================
// HTTP Convenience Methods — prove the OneAuth→HTTP bridge works
// =============================================================================

// TestOneAuth_IntrospectionHTTPHandler verifies that introspection works
// via OneAuth's HTTP handler — full HTTP round-trip, no old-style APIAuth.
func TestOneAuth_IntrospectionHTTPHandler(t *testing.T) {
	oa := newTestOneAuth(t)
	handler := oa.IntrospectionHTTPHandler()

	token, _, _ := oa.Issuer.CreateAccessToken("http-user", []string{"read"}, nil)

	// Introspect via HTTP
	rr := postIntrospect(t, handler, token, "test-client", "test-client-secret-32chars-min!!")
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"active":true`)
	assert.Contains(t, rr.Body.String(), `"sub":"http-user"`)
}

// TestOneAuth_RevocationHTTPHandler verifies that revocation works
// via OneAuth's HTTP handler — full HTTP round-trip.
func TestOneAuth_RevocationHTTPHandler(t *testing.T) {
	oa := newTestOneAuth(t)
	revHandler := oa.RevocationHTTPHandler()
	introHandler := oa.IntrospectionHTTPHandler()

	token, _, _ := oa.Issuer.CreateAccessToken("revoke-http", []string{"read"}, nil)

	// Revoke via HTTP
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-client", "test-client-secret-32chars-min!!")
	rr := httptest.NewRecorder()
	revHandler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Introspect — should be inactive
	rr = postIntrospect(t, introHandler, token, "test-client", "test-client-secret-32chars-min!!")
	assert.Contains(t, rr.Body.String(), `"active":false`)
}

// TestOneAuth_HTTPMiddleware verifies that token validation works
// via OneAuth's HTTP middleware — full HTTP round-trip.
func TestOneAuth_HTTPMiddleware(t *testing.T) {
	oa := newTestOneAuth(t)
	mw := oa.HTTPMiddleware()

	token, _, _ := oa.Issuer.CreateAccessToken("mw-user", []string{"read"}, nil)

	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := apiauth.GetUserIDFromAPIContext(r.Context())
		w.Write([]byte(userID))
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "mw-user", rr.Body.String())
}

// TestOneAuth_AuthenticateClient verifies client authentication via library call.
func TestOneAuth_AuthenticateClient(t *testing.T) {
	oa := newTestOneAuth(t)

	assert.NoError(t, oa.Authenticator.AuthenticateClient("test-client", "test-client-secret-32chars-min!!"))
	assert.Error(t, oa.Authenticator.AuthenticateClient("test-client", "wrong"))
	assert.Error(t, oa.Authenticator.AuthenticateClient("unknown", "secret"))
}
