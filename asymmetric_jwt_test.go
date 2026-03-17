package oneauth_test

// Tests for asymmetric JWT signing: MintResourceTokenWithKey (RS256/ES256), APIAuth
// asymmetric token creation/validation, and APIMiddleware multi-tenant validation
// with mixed algorithm support and algorithm confusion attack prevention.

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/utils"
)

// ============================================================================
// MintResourceTokenWithKey tests
// ============================================================================

// TestMintResourceTokenWithKey_RS256 verifies that MintResourceTokenWithKey produces
// a valid RS256-signed JWT that can be verified with the corresponding public key.
func TestMintResourceTokenWithKey_RS256(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	pubKey, _ := utils.ParsePublicKeyPEM(pubPEM)

	tokenStr, err := oa.MintResourceTokenWithKey("user-1", "app-rsa", privKey, oa.AppQuota{MaxRooms: 5}, []string{"read"})
	if err != nil {
		t.Fatalf("MintResourceTokenWithKey: %v", err)
	}

	// Verify with public key
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("Expected RS256, got %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", claims["sub"])
	}
	if claims["client_id"] != "app-rsa" {
		t.Errorf("client_id = %v, want app-rsa", claims["client_id"])
	}
}

// TestMintResourceTokenWithKey_ES256 verifies that MintResourceTokenWithKey produces
// a valid ES256-signed JWT that can be verified with the corresponding ECDSA public key.
func TestMintResourceTokenWithKey_ES256(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair: %v", err)
	}
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	pubKey, _ := utils.ParsePublicKeyPEM(pubPEM)

	tokenStr, err := oa.MintResourceTokenWithKey("user-2", "app-ec", privKey, oa.AppQuota{}, []string{"write"})
	if err != nil {
		t.Fatalf("MintResourceTokenWithKey: %v", err)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Fatalf("Expected ES256, got %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if token.Claims.(jwt.MapClaims)["sub"] != "user-2" {
		t.Error("sub mismatch")
	}
}

// TestMintResourceTokenWithKey_WrongKey verifies that a token signed with one RSA private key
// is rejected when verified with a different RSA public key.
func TestMintResourceTokenWithKey_WrongKey(t *testing.T) {
	privPEM, _, _ := utils.GenerateRSAKeyPair(2048)
	_, otherPubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	otherPub, _ := utils.ParsePublicKeyPEM(otherPubPEM)

	tokenStr, _ := oa.MintResourceTokenWithKey("user-1", "app-rsa", privKey, oa.AppQuota{}, []string{"read"})

	// Verify with wrong public key — should fail
	_, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return otherPub, nil
	})
	if err == nil {
		t.Fatal("Expected verification to fail with wrong key")
	}
}

// TestMintResourceTokenWithKey_BackwardsCompat verifies that the original MintResourceToken
// (HS256) API still works correctly alongside the new asymmetric key API.
func TestMintResourceTokenWithKey_BackwardsCompat(t *testing.T) {
	// MintResourceToken (old API) should still work
	tokenStr, err := oa.MintResourceToken("user-1", "app-hs", "my-secret", oa.AppQuota{MaxRooms: 3}, []string{"read"})
	if err != nil {
		t.Fatalf("MintResourceToken: %v", err)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Fatalf("Expected HS256, got %v", token.Header["alg"])
		}
		return []byte("my-secret"), nil
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if token.Claims.(jwt.MapClaims)["sub"] != "user-1" {
		t.Error("sub mismatch")
	}
}

// ============================================================================
// APIAuth asymmetric signing tests
// ============================================================================

// TestAPIAuth_RS256_Signing verifies that APIAuth can create and validate RS256 access tokens
// with correct user ID and scopes.
func TestAPIAuth_RS256_Signing(t *testing.T) {
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	pubKey, _ := utils.ParsePublicKeyPEM(pubPEM)

	auth := &oa.APIAuth{
		JWTSigningAlg: "RS256",
		JWTSigningKey: privKey,
		JWTVerifyKey:  pubKey,
		JWTIssuer:     "test",
	}

	tokenStr, _, err := auth.CreateAccessToken("user-rsa", []string{"read"})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	userID, scopes, err := auth.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if userID != "user-rsa" {
		t.Errorf("userID = %s, want user-rsa", userID)
	}
	if len(scopes) != 1 || scopes[0] != "read" {
		t.Errorf("scopes = %v, want [read]", scopes)
	}
}

// TestAPIAuth_ES256_Signing verifies that APIAuth can create and validate ES256 access tokens
// with correct user ID and scopes.
func TestAPIAuth_ES256_Signing(t *testing.T) {
	privPEM, pubPEM, _ := utils.GenerateECDSAKeyPair()
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	pubKey, _ := utils.ParsePublicKeyPEM(pubPEM)

	auth := &oa.APIAuth{
		JWTSigningAlg: "ES256",
		JWTSigningKey: privKey,
		JWTVerifyKey:  pubKey,
	}

	tokenStr, _, err := auth.CreateAccessToken("user-ec", []string{"write"})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	userID, scopes, err := auth.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if userID != "user-ec" {
		t.Errorf("userID = %s, want user-ec", userID)
	}
	if len(scopes) != 1 || scopes[0] != "write" {
		t.Errorf("scopes = %v, want [write]", scopes)
	}
}

// TestAPIAuth_RS256_RejectsHMAC verifies that an RS256-signed token is rejected
// when validated by an HMAC-configured APIAuth instance.
func TestAPIAuth_RS256_RejectsHMAC(t *testing.T) {
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	pubKey, _ := utils.ParsePublicKeyPEM(pubPEM)

	auth := &oa.APIAuth{
		JWTSigningAlg: "RS256",
		JWTSigningKey: privKey,
		JWTVerifyKey:  pubKey,
	}

	// Create a valid RS256 token, then try to validate with HMAC-configured auth
	tokenStr, _, _ := auth.CreateAccessToken("user-1", []string{"read"})

	hmacAuth := &oa.APIAuth{JWTSecretKey: "some-secret"}
	_, _, err := hmacAuth.ValidateAccessToken(tokenStr)
	if err == nil {
		t.Fatal("Expected HMAC auth to reject RS256 token")
	}
}

// TestAPIAuth_ValidateAccessTokenFull_RS256 verifies that ValidateAccessTokenFull returns
// custom claims (e.g., client_id) alongside the user ID for RS256 tokens.
func TestAPIAuth_ValidateAccessTokenFull_RS256(t *testing.T) {
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	pubKey, _ := utils.ParsePublicKeyPEM(pubPEM)

	auth := &oa.APIAuth{
		JWTSigningAlg: "RS256",
		JWTSigningKey: privKey,
		JWTVerifyKey:  pubKey,
		CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
			return map[string]any{"client_id": "app-1"}, nil
		},
	}

	tokenStr, _, _ := auth.CreateAccessToken("user-1", []string{"read"})
	userID, _, custom, err := auth.ValidateAccessTokenFull(tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessTokenFull: %v", err)
	}
	if userID != "user-1" {
		t.Errorf("userID = %s, want user-1", userID)
	}
	if custom["client_id"] != "app-1" {
		t.Errorf("client_id = %v, want app-1", custom["client_id"])
	}
}

// ============================================================================
// APIMiddleware multi-tenant asymmetric validation tests
// ============================================================================

// TestAPIMiddleware_RS256_MultiTenant verifies that APIMiddleware validates RS256 tokens
// from registered apps using the KeyStore for public key lookup.
func TestAPIMiddleware_RS256_MultiTenant(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

	// Register an RS256 app with its public key
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	ks.RegisterKey("app-rsa", pubPEM, "RS256")

	// Mint a token with the private key
	tokenStr, err := oa.MintResourceTokenWithKey("user-1", "app-rsa", privKey, oa.AppQuota{}, []string{"read"})
	if err != nil {
		t.Fatalf("MintResourceTokenWithKey: %v", err)
	}

	middleware := &oa.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := oa.GetUserIDFromAPIContext(r.Context())
		if userID != "user-1" {
			t.Errorf("userID = %s, want user-1", userID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

// TestAPIMiddleware_ES256_MultiTenant verifies that APIMiddleware validates ES256 tokens
// from registered apps using the KeyStore for public key lookup.
func TestAPIMiddleware_ES256_MultiTenant(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

	privPEM, pubPEM, _ := utils.GenerateECDSAKeyPair()
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	ks.RegisterKey("app-ec", pubPEM, "ES256")

	tokenStr, _ := oa.MintResourceTokenWithKey("user-2", "app-ec", privKey, oa.AppQuota{}, []string{"write"})

	middleware := &oa.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

// TestAPIMiddleware_MixedAlgorithms verifies that APIMiddleware correctly validates tokens
// from HS256, RS256, and ES256 apps coexisting in the same KeyStore.
func TestAPIMiddleware_MixedAlgorithms(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

	// Register HS256 app
	ks.RegisterKey("app-hs", []byte("hs-secret"), "HS256")

	// Register RS256 app
	rsaPrivPEM, rsaPubPEM, _ := utils.GenerateRSAKeyPair(2048)
	rsaPrivKey, _ := utils.ParsePrivateKeyPEM(rsaPrivPEM)
	ks.RegisterKey("app-rsa", rsaPubPEM, "RS256")

	// Register ES256 app
	ecPrivPEM, ecPubPEM, _ := utils.GenerateECDSAKeyPair()
	ecPrivKey, _ := utils.ParsePrivateKeyPEM(ecPrivPEM)
	ks.RegisterKey("app-ec", ecPubPEM, "ES256")

	middleware := &oa.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name  string
		token string
	}{
		{"HS256", mustMintHS256(t, "user-1", "app-hs", "hs-secret")},
		{"RS256", mustMintWithKey(t, "user-2", "app-rsa", rsaPrivKey)},
		{"ES256", mustMintWithKey(t, "user-3", "app-ec", ecPrivKey)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestAPIMiddleware_AlgorithmConfusion verifies that the middleware rejects algorithm confusion
// attacks where an attacker uses the RS256 public key as an HS256 HMAC secret to forge tokens.
func TestAPIMiddleware_AlgorithmConfusion(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()

	// Register app as RS256
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	ks.RegisterKey("app-rsa", pubPEM, "RS256")

	// Try to forge a token using HS256 with the public key as the HMAC secret
	// This is the classic algorithm confusion attack
	forgedToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       "attacker",
		"client_id": "app-rsa",
		"type":      "access",
		"scopes":    []string{"admin"},
	})
	forgedStr, _ := forgedToken.SignedString(pubPEM) // Using PEM bytes as HMAC key

	middleware := &oa.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called for forged token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+forgedStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for algorithm confusion attack, got %d", rr.Code)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func mustMintHS256(t *testing.T, userID, clientID, secret string) string {
	t.Helper()
	tok, err := oa.MintResourceToken(userID, clientID, secret, oa.AppQuota{}, []string{"read"})
	if err != nil {
		t.Fatalf("MintResourceToken: %v", err)
	}
	return tok
}

func mustMintWithKey(t *testing.T, userID, clientID string, key any) string {
	t.Helper()
	tok, err := oa.MintResourceTokenWithKey(userID, clientID, key, oa.AppQuota{}, []string{"read"})
	if err != nil {
		t.Fatalf("MintResourceTokenWithKey: %v", err)
	}
	return tok
}

// Verify unused imports are legitimate
var _ *rsa.PublicKey
var _ *ecdsa.PublicKey
