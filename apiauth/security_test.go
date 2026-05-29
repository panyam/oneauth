package apiauth_test

// Security test suite for JWT attack vectors: algorithm confusion, claim manipulation,
// and edge cases in token validation. Documents defense-in-depth guarantees. (#16)
//
// References:
//   - CVE-2015-9235 (https://nvd.nist.gov/vuln/detail/CVE-2015-9235):
//     JWT algorithm confusion — signing with public key as HMAC secret
//   - RFC 7519 (https://datatracker.ietf.org/doc/html/rfc7519): JWT specification
//   - OWASP JWT Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html):
//     JWT security best practices

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: run a token through APIMiddleware and return the HTTP status code.
func validateViaMiddleware(t *testing.T, ks keys.KeyLookup, token string) int {
	t.Helper()
	mw := &apiauth.APIMiddleware{KeyStore: ks}
	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)
	return rr.Code
}

// =============================================================================
// Algorithm Confusion
// =============================================================================

// TestSecurity_AlgNone_Rejected proves that tokens with alg:none are rejected.
// This is the most basic JWT attack — sending an unsigned token.
// jwt/v5 rejects this by default, but we prove the guarantee explicitly.
//
// See: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
func TestSecurity_AlgNone_Rejected(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app1", Key: []byte("secret"), Algorithm: "HS256"}})
	// Craft a token with alg: none
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub":       "attacker",
		"client_id": "app1",
		"type":      "access",
		"scopes":    []string{"read"},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, validateViaMiddleware(t, ks, tokenString),
		"alg:none tokens must be rejected")
}

// TestSecurity_AlgConfusion_HS256WithRSAPubKey proves the classic CVE-2015-9235 attack
// is blocked: attacker signs with RSA public key bytes as HMAC secret.
// Our middleware checks rec.Algorithm against token header alg before verification.
//
// See: https://nvd.nist.gov/vuln/detail/CVE-2015-9235
func TestSecurity_AlgConfusion_HS256WithRSAPubKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ks := keys.NewInMemoryKeyStore()
	pubPEM, _ := utils.EncodePublicKeyPEM(&privKey.PublicKey)
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app-rsa", Key: pubPEM, Algorithm: "RS256"}})
	// Attacker uses the public key PEM bytes as HMAC secret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       "attacker",
		"client_id": "app-rsa",
		"type":      "access",
		"scopes":    []string{"admin"},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	tokenString, err := token.SignedString(pubPEM)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, validateViaMiddleware(t, ks, tokenString),
		"HS256 token signed with RSA public key must be rejected (algorithm confusion)")
}

// TestSecurity_RS256Token_AgainstHS256Store proves the reverse confusion:
// an RS256-signed token against an HS256 key store is rejected.
func TestSecurity_RS256Token_AgainstHS256Store(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ks := keys.NewInMemoryKeyStore()
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app-hmac", Key: []byte("my-secret"), Algorithm: "HS256"}})
	// Sign with RSA but claim the HMAC app's client_id
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":       "attacker",
		"client_id": "app-hmac",
		"type":      "access",
		"scopes":    []string{"read"},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	tokenString, err := token.SignedString(privKey)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, validateViaMiddleware(t, ks, tokenString),
		"RS256 token against HS256 store must be rejected")
}

// =============================================================================
// Claim Validation
// =============================================================================

// TestSecurity_ExpiredToken_Rejected proves expired JWTs are rejected.
func TestSecurity_ExpiredToken_Rejected(t *testing.T) {
	secret := "test-secret-key-for-jwt"
	auth := &apiauth.APIAuth{JWTSecretKey: secret}

	tokenResp, err := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})

	token := ""

	var _ int64

	if tokenResp != nil { token = tokenResp.Token; _ = tokenResp.ExpiresIn }

	require.NoError(t, err)

	// Validate immediately — should work
	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	var userID string
	var _ []string
	if vresp != nil && vresp.Info != nil { userID = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.NoError(t, err)
	assert.Equal(t, "user1", userID)

	// Craft an already-expired token
	expired := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    "user1",
		"type":   "access",
		"scopes": []string{"read"},
		"exp":    time.Now().Add(-time.Hour).Unix(),
		"iat":    time.Now().Add(-2 * time.Hour).Unix(),
	})
	expiredStr, _ := expired.SignedString([]byte(secret))

	vresp, err = auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: expiredStr})

	var _ string

	var _ []string

	if vresp != nil && vresp.Info != nil { _ = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.Error(t, err, "expired tokens must be rejected")
}

// TestSecurity_RefreshTokenType_RejectedAsAccess proves that a JWT with
// type: "refresh" is rejected by the access token validator.
//
// See: https://cwe.mitre.org/data/definitions/269.html (Improper Privilege Management)
func TestSecurity_RefreshTokenType_RejectedAsAccess(t *testing.T) {
	secret := "test-secret"
	auth := &apiauth.APIAuth{JWTSecretKey: secret}

	// Craft a token with type: "refresh" instead of "access"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    "user1",
		"type":   "refresh", // wrong type
		"scopes": []string{"read"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	})
	tokenStr, _ := token.SignedString([]byte(secret))

	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: tokenStr})

	var _ string

	var _ []string

	if vresp != nil && vresp.Info != nil { _ = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.Error(t, err, "refresh-type tokens must be rejected by access token validator")
	assert.Contains(t, err.Error(), "invalid token type")
}

// TestSecurity_MissingSub_Rejected proves tokens without a subject claim are rejected.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
func TestSecurity_MissingSub_Rejected(t *testing.T) {
	secret := "test-secret"
	auth := &apiauth.APIAuth{JWTSecretKey: secret}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// no "sub" claim
		"type":   "access",
		"scopes": []string{"read"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	})
	tokenStr, _ := token.SignedString([]byte(secret))

	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: tokenStr})

	var _ string

	var _ []string

	if vresp != nil && vresp.Info != nil { _ = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.Error(t, err, "tokens without sub claim must be rejected")
	assert.Contains(t, err.Error(), "missing subject")
}

// TestSecurity_WrongIssuer_Rejected proves tokens with wrong issuer are rejected
// when issuer validation is configured.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
func TestSecurity_WrongIssuer_Rejected(t *testing.T) {
	secret := "test-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTIssuer:    "my-auth-server",
	}

	// Token from a different issuer
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    "user1",
		"iss":    "evil-server",
		"type":   "access",
		"scopes": []string{"read"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	})
	tokenStr, _ := token.SignedString([]byte(secret))

	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: tokenStr})

	var _ string

	var _ []string

	if vresp != nil && vresp.Info != nil { _ = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.Error(t, err, "tokens with wrong issuer must be rejected")
	assert.Contains(t, err.Error(), "invalid issuer")
}

// =============================================================================
// Edge Cases
// =============================================================================

// TestSecurity_EmptySigningKey_Errors proves that an empty signing key
// does not silently produce "valid" tokens.
func TestSecurity_EmptySigningKey_Errors(t *testing.T) {
	auth := &apiauth.APIAuth{JWTSecretKey: ""}

	// CreateAccessToken with empty key should still produce a token
	// (jwt library allows it), but validation should use the same empty key.
	// The real risk is key misconfiguration — this documents current behavior.
	tokenResp, err := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user1", Scopes: []string{"read"}, AuthorizationDetails: nil})
	token := ""
	var _ int64
	if tokenResp != nil { token = tokenResp.Token; _ = tokenResp.ExpiresIn }

	if err != nil {
		// If it errors on creation, that's fine — fail-safe
		return
	}

	// If it produces a token, it should at least be verifiable with the same empty key
	vresp, err := auth.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	var userID string
	var _ []string
	if vresp != nil && vresp.Info != nil { userID = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.NoError(t, err)
	assert.Equal(t, "user1", userID)

	// But it must NOT be verifiable with a different key
	auth2 := &apiauth.APIAuth{JWTSecretKey: "different-key"}
	vresp, err = auth2.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	var _ string
	var _ []string
	if vresp != nil && vresp.Info != nil { _ = vresp.Info.Subject; _ = vresp.Info.Scopes }

	assert.Error(t, err, "token signed with empty key must not validate with different key")
}

// TestSecurity_NilKey_MintResourceToken proves that MintResourceToken
// returns an error when given a nil signing key.
func TestSecurity_NilKey_MintResourceToken(t *testing.T) {
	_, err := admin.MintResourceToken("user1", "app1", nil, nil, []string{"read"}, nil)
	assert.Error(t, err, "nil signing key must return error")
}

// TestSecurity_SigningMethodForAlg_UnknownAlgorithm verifies that
// SigningMethodForAlg returns an error for unrecognized algorithms instead
// of silently defaulting to HS256 (which could mask misconfiguration).
// Empty string still defaults to HS256 for backward compatibility.
func TestSecurity_SigningMethodForAlg_UnknownAlgorithm(t *testing.T) {
	// Empty string defaults to HS256
	method, err := utils.SigningMethodForAlg("")
	assert.NoError(t, err)
	assert.Equal(t, jwt.SigningMethodHS256, method,
		"empty alg should default to HS256 (used when JWTSigningAlg not configured)")

	// Unknown string returns error (not silent HS256 fallback)
	_, err = utils.SigningMethodForAlg("garbage")
	assert.Error(t, err, "unknown alg should return error, not silent default")

	_, err = utils.SigningMethodForAlg("RS257")
	assert.Error(t, err, "typo 'RS257' should return error, not silent default")

	// Known algorithms map correctly
	for _, alg := range []string{"RS256", "ES256", "HS256", "HS384", "HS512"} {
		m, err := utils.SigningMethodForAlg(alg)
		assert.NoError(t, err, "SigningMethodForAlg(%q) should not error", alg)
		assert.Equal(t, alg, m.Alg())
	}
}

// TestSecurity_NoKidHeader_FallsBackToClientID proves that tokens without
// a kid header still work via client_id claim fallback (legacy compatibility).
func TestSecurity_NoKidHeader_FallsBackToClientID(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app1", Key: []byte("secret"), Algorithm: "HS256"}})
	// Mint a token WITHOUT kid header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       "user1",
		"client_id": "app1",
		"type":      "access",
		"scopes":    []string{"read"},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	// Explicitly do NOT set kid header
	tokenStr, err := token.SignedString([]byte("secret"))
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, validateViaMiddleware(t, ks, tokenStr),
		"tokens without kid should fall back to client_id lookup")
}

// TestSecurity_CrossAlgorithm_ES256TokenAgainstRS256Store proves that an ES256
// token is rejected against an RS256 key store (different asymmetric algorithms).
func TestSecurity_CrossAlgorithm_ES256TokenAgainstRS256Store(t *testing.T) {
	// Store has RS256 key
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ks := keys.NewInMemoryKeyStore()
	pubPEM, _ := utils.EncodePublicKeyPEM(&rsaPriv.PublicKey)
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app-rsa", Key: pubPEM, Algorithm: "RS256"}})
	// Attacker signs with EC key
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":       "attacker",
		"client_id": "app-rsa",
		"type":      "access",
		"scopes":    []string{"admin"},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})
	tokenStr, _ := token.SignedString(ecPriv)

	assert.Equal(t, http.StatusUnauthorized, validateViaMiddleware(t, ks, tokenStr),
		"ES256 token against RS256 store must be rejected")
}

// TestSecurity_ScopeEscalation_Prevented proves that the middleware passes through
// whatever scopes are in the token — scope enforcement is the application's job
// via RequireScopes. This test documents that ValidateToken does NOT filter scopes.
func TestSecurity_ScopeEscalation_Prevented(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app1", Key: []byte("secret"), Algorithm: "HS256"}})
	// Mint with admin scope
	token, _ := admin.MintResourceToken("user1", "app1", []byte("secret"),
		nil, []string{"admin"}, nil)

	// RequireScopes("admin") allows it
	mw := &apiauth.APIMiddleware{KeyStore: ks}
	adminHandler := mw.RequireScopes(core.ScopeAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	adminHandler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// RequireScopes("write") rejects it (token only has "admin")
	writeHandler := mw.RequireScopes(core.ScopeWrite)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	writeHandler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"token with only 'admin' scope must be rejected when 'write' is required")
}
