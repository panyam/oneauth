package apiauth_test

// Tests for JWT token revocation via blacklist (#23).
// Access tokens are stateless JWTs — once issued, they're valid until expiry.
// The blacklist allows immediate revocation by tracking jti (JWT ID) claims.
//
// References:
//   - RFC 7519 §4.1.7 (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7):
//     "jti" (JWT ID) Claim — unique identifier for the JWT
//   - CWE-613 (https://cwe.mitre.org/data/definitions/613.html):
//     Insufficient Session Expiration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Core blacklist unit tests (pass immediately)
// =============================================================================

// TestInMemoryBlacklist_RevokeAndCheck verifies basic revoke/check lifecycle.
func TestInMemoryBlacklist_RevokeAndCheck(t *testing.T) {
	bl := core.NewInMemoryBlacklist()

	assert.False(t, bl.IsRevoked("jti-1"))

	bl.Revoke("jti-1", time.Now().Add(time.Minute))
	assert.True(t, bl.IsRevoked("jti-1"))
	assert.False(t, bl.IsRevoked("jti-2"))
}

// TestInMemoryBlacklist_AutoExpiry verifies that expired entries are no longer
// reported as revoked (the token would have expired anyway).
func TestInMemoryBlacklist_AutoExpiry(t *testing.T) {
	bl := core.NewInMemoryBlacklist()

	bl.Revoke("jti-1", time.Now().Add(50*time.Millisecond))
	assert.True(t, bl.IsRevoked("jti-1"))

	time.Sleep(60 * time.Millisecond)
	assert.False(t, bl.IsRevoked("jti-1"), "expired blacklist entry should not be reported as revoked")
}

// TestInMemoryBlacklist_Cleanup verifies that CleanupExpired removes stale entries.
func TestInMemoryBlacklist_Cleanup(t *testing.T) {
	bl := core.NewInMemoryBlacklist()

	bl.Revoke("jti-1", time.Now().Add(50*time.Millisecond))
	bl.Revoke("jti-2", time.Now().Add(time.Hour))
	assert.Equal(t, 2, bl.Len())

	time.Sleep(60 * time.Millisecond)
	bl.CleanupExpired()
	assert.Equal(t, 1, bl.Len(), "expired entry should be cleaned up")
	assert.False(t, bl.IsRevoked("jti-1"))
	assert.True(t, bl.IsRevoked("jti-2"))
}

// =============================================================================
// APIAuth blacklist integration (FAIL before fix)
// =============================================================================

// TestBlacklist_JTIInAccessToken verifies that minted access tokens include
// a jti (JWT ID) claim, which is required for blacklisting individual tokens.
//
// BEFORE FIX: no jti claim in tokens
// AFTER FIX: jti claim present and unique per token
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
func TestBlacklist_JTIInAccessToken(t *testing.T) {
	auth := newAPIAuthFixture(apiauth.OneAuthConfig{SigningKey: []byte("test-secret"), SigningAlg: "HS256"}, nil)

	token1Resp, err := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})

	token1 := ""

	var _ int64

	if token1Resp != nil { token1 = token1Resp.Token; _ = token1Resp.ExpiresIn }

	require.NoError(t, err)

	token2Resp, err := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})

	token2 := ""

	var _ int64

	if token2Resp != nil { token2 = token2Resp.Token; _ = token2Resp.ExpiresIn }

	require.NoError(t, err)

	// Parse tokens to extract jti
	parser := jwt.NewParser()
	parsed1, _, _ := parser.ParseUnverified(token1, jwt.MapClaims{})
	parsed2, _, _ := parser.ParseUnverified(token2, jwt.MapClaims{})

	claims1 := parsed1.Claims.(jwt.MapClaims)
	claims2 := parsed2.Claims.(jwt.MapClaims)

	jti1, ok := claims1["jti"].(string)
	assert.True(t, ok, "access token must include jti claim")
	assert.NotEmpty(t, jti1)

	jti2, _ := claims2["jti"].(string)
	assert.NotEqual(t, jti1, jti2, "each token must have a unique jti")
}

// TestBlacklist_RevokedTokenRejected verifies that a revoked access token
// is rejected by ValidateAccessToken when a blacklist is configured.
//
// BEFORE FIX: no Blacklist field on APIAuth, revoked tokens accepted
// AFTER FIX: revoked tokens return error
//
// See: https://cwe.mitre.org/data/definitions/613.html
func TestBlacklist_RevokedTokenRejected(t *testing.T) {
	bl := core.NewInMemoryBlacklist()
	auth := newAPIAuthFixture(apiauth.OneAuthConfig{SigningKey: []byte("test-secret"), SigningAlg: "HS256", Blacklist: bl}, nil)

	tokenResp, err := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})

	token := ""

	var _ int64

	if tokenResp != nil { token = tokenResp.Token; _ = tokenResp.ExpiresIn }

	require.NoError(t, err)

	// Token should work before revocation
	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	var userID string
	var _ []string
	if vresp != nil && vresp.Info != nil { userID = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.NoError(t, err)
	assert.Equal(t, "user1", userID)

	// Extract jti and revoke
	parser := jwt.NewParser()
	parsed, _, _ := parser.ParseUnverified(token, jwt.MapClaims{})
	jti := parsed.Claims.(jwt.MapClaims)["jti"].(string)
	bl.Revoke(jti, time.Now().Add(time.Hour))

	// Token should now be rejected
	vresp, err = auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	var _ string
	var _ []string
	if vresp != nil && vresp.Info != nil { _ = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.Error(t, err, "revoked token should be rejected")
	assert.Contains(t, err.Error(), "revoked")
}

// TestBlacklist_NonRevokedTokenAccepted verifies that the blacklist doesn't
// produce false positives — tokens that haven't been revoked still work.
func TestBlacklist_NonRevokedTokenAccepted(t *testing.T) {
	bl := core.NewInMemoryBlacklist()
	auth := newAPIAuthFixture(apiauth.OneAuthConfig{SigningKey: []byte("test-secret"), SigningAlg: "HS256", Blacklist: bl}, nil)

	tokenResp, err := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})

	token := ""

	var _ int64

	if tokenResp != nil { token = tokenResp.Token; _ = tokenResp.ExpiresIn }

	require.NoError(t, err)

	// Revoke a DIFFERENT token
	bl.Revoke("some-other-jti", time.Now().Add(time.Hour))

	// Our token should still work
	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	var userID string
	var _ []string
	if vresp != nil && vresp.Info != nil { userID = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.NoError(t, err)
	assert.Equal(t, "user1", userID)
}

// TestBlacklist_NoBlacklistConfigured verifies backward compatibility:
// when no blacklist is set, tokens are validated normally (no revocation check).
func TestBlacklist_NoBlacklistConfigured(t *testing.T) {
	auth := newAPIAuthFixture(apiauth.OneAuthConfig{SigningKey: []byte("test-secret"), SigningAlg: "HS256"}, nil)
	// No Blacklist field set

	tokenResp, err := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})

	token := ""

	var _ int64

	if tokenResp != nil { token = tokenResp.Token; _ = tokenResp.ExpiresIn }

	require.NoError(t, err)

	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})

	var userID string

	var _ []string

	if vresp != nil && vresp.Info != nil { userID = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.NoError(t, err)
	assert.Equal(t, "user1", userID)
}

// TestBlacklist_MiddlewareChecksBlacklist verifies that APIMiddleware also
// checks the blacklist, not just APIAuth.ValidateAccessToken.
//
// BEFORE FIX: APIMiddleware has no Blacklist field
// AFTER FIX: middleware rejects revoked tokens with 401
//
// See: https://cwe.mitre.org/data/definitions/613.html
func TestBlacklist_MiddlewareChecksBlacklist(t *testing.T) {
	bl := core.NewInMemoryBlacklist()
	secret := "test-secret"

	auth := newAPIAuthFixture(apiauth.OneAuthConfig{SigningKey: []byte(secret), SigningAlg: "HS256", Blacklist: bl}, nil)

	mw := &apiauth.APIMiddleware{
		JWTSecretKey: secret,
		Blacklist:    bl,
	}

	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tokenResp, _ := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})


	token := ""


	if tokenResp != nil { token = tokenResp.Token }

	// Should work before revocation
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Revoke via jti
	parser := jwt.NewParser()
	parsed, _, _ := parser.ParseUnverified(token, jwt.MapClaims{})
	jti := parsed.Claims.(jwt.MapClaims)["jti"].(string)
	bl.Revoke(jti, time.Now().Add(time.Hour))

	// Should be rejected after revocation
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"middleware should reject revoked tokens")
}

// TestBlacklist_ValidateAccessTokenFull_ChecksBlacklist verifies that
// ValidateAccessTokenFull also checks the blacklist.
func TestBlacklist_ValidateAccessTokenFull_ChecksBlacklist(t *testing.T) {
	bl := core.NewInMemoryBlacklist()
	auth := newAPIAuthFixture(apiauth.OneAuthConfig{SigningKey: []byte("test-secret"), SigningAlg: "HS256", Blacklist: bl}, nil)

	tokenResp, _ := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})


	token := ""


	if tokenResp != nil { token = tokenResp.Token }

	// Extract and revoke
	parser := jwt.NewParser()
	parsed, _, _ := parser.ParseUnverified(token, jwt.MapClaims{})
	jti := parsed.Claims.(jwt.MapClaims)["jti"].(string)
	bl.Revoke(jti, time.Now().Add(time.Hour))

	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})

	var _ string

	var _ []string

	var _ map[string]any

	if vresp != nil && vresp.Info != nil { _ = vresp.Info.Subject; _ = vresp.Info.Scopes; _ = vresp.Info.CustomClaims }

	assert.Error(t, err, "ValidateAccessTokenFull should also check blacklist")
}

// TestBlacklist_MultiTenantMiddleware verifies blacklist works with
// KeyStore-based multi-tenant validation.
func TestBlacklist_MultiTenantMiddleware(t *testing.T) {
	bl := core.NewInMemoryBlacklist()
	ks := keys.NewInMemoryKeyStore()
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app1", Key: []byte("secret1"), Algorithm: "HS256"}})
	mw := &apiauth.APIMiddleware{
		KeyStore:  ks,
		Blacklist: bl,
	}

	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Mint a token for app1
	token := mintTestJWT(t, "secret1", "user1", "app1")

	// Works before revocation
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Revoke
	parser := jwt.NewParser()
	parsed, _, _ := parser.ParseUnverified(token, jwt.MapClaims{})
	jti := parsed.Claims.(jwt.MapClaims)["jti"].(string)
	bl.Revoke(jti, time.Now().Add(time.Hour))

	// Rejected
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// mintTestJWT creates a test JWT with jti for blacklist testing.
func mintTestJWT(t *testing.T, secret, userID, clientID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":       userID,
		"client_id": clientID,
		"type":      "access",
		"scopes":    []string{"read"},
		"jti":       "test-jti-" + userID,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}
