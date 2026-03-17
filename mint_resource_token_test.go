package oneauth_test

// Tests for MintResourceToken: HS256 token minting, claim population, quota handling,
// KeyStore-based verification, and rejection of tokens signed with incorrect secrets.

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	oa "github.com/panyam/oneauth"
)

// TestMintResourceToken_Basic verifies that MintResourceToken produces a valid HS256 JWT
// with the correct sub, client_id, type, and quota claims.
func TestMintResourceToken_Basic(t *testing.T) {
	token, err := oa.MintResourceToken("user-123", "app-abc", "my-secret", oa.AppQuota{
		MaxRooms:   10,
		MaxMsgRate: 30.0,
	}, []string{"read", "write"})
	if err != nil {
		t.Fatalf("MintResourceToken failed: %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}

	// Parse and verify
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte("my-secret"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "user-123" {
		t.Errorf("Expected sub user-123, got %v", claims["sub"])
	}
	if claims["client_id"] != "app-abc" {
		t.Errorf("Expected client_id app-abc, got %v", claims["client_id"])
	}
	if claims["type"] != "access" {
		t.Errorf("Expected type access, got %v", claims["type"])
	}
	if claims["max_rooms"] != float64(10) {
		t.Errorf("Expected max_rooms 10, got %v", claims["max_rooms"])
	}
	if claims["max_msg_rate"] != float64(30) {
		t.Errorf("Expected max_msg_rate 30, got %v", claims["max_msg_rate"])
	}
}

// TestMintResourceToken_NoQuota verifies that zero-value quota fields are omitted from JWT claims.
func TestMintResourceToken_NoQuota(t *testing.T) {
	token, err := oa.MintResourceToken("user-1", "app-1", "secret", oa.AppQuota{}, []string{"read"})
	if err != nil {
		t.Fatalf("MintResourceToken failed: %v", err)
	}

	parsed, _ := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte("secret"), nil
	})
	claims := parsed.Claims.(jwt.MapClaims)

	// Zero-value quotas should not be in claims
	if _, exists := claims["max_rooms"]; exists {
		t.Error("Zero max_rooms should not be in claims")
	}
	if _, exists := claims["max_msg_rate"]; exists {
		t.Error("Zero max_msg_rate should not be in claims")
	}
}

// TestMintResourceToken_VerifiableByMiddleware verifies that a minted token can be validated
// using a KeyStore-based key function, simulating the APIMiddleware verification flow.
func TestMintResourceToken_VerifiableByMiddleware(t *testing.T) {
	secret := "shared-secret-between-app-and-resource-server"
	clientID := "app-excaliframe"

	// App mints token
	token, err := oa.MintResourceToken("user-42", clientID, secret, oa.AppQuota{}, []string{"read"})
	if err != nil {
		t.Fatalf("MintResourceToken failed: %v", err)
	}

	// Resource server verifies using KeyStore
	ks := oa.NewInMemoryKeyStore()
	ks.RegisterKey(clientID, []byte(secret), "HS256")

	// Parse with KeyStore-based keyfunc (mimics what APIMiddleware does)
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		claims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			return nil, oa.ErrKeyNotFound
		}
		cid, _ := claims["client_id"].(string)
		expectedAlg, err := ks.GetExpectedAlg(cid)
		if err != nil {
			return nil, err
		}
		if t.Header["alg"] != expectedAlg {
			return nil, oa.ErrAlgorithmMismatch
		}
		return ks.GetVerifyKey(cid)
	})
	if err != nil {
		t.Fatalf("KeyStore-based verification failed: %v", err)
	}
	if !parsed.Valid {
		t.Error("Token should be valid")
	}
}

// TestMintResourceToken_WrongSecretRejected verifies that a token signed with one secret
// is rejected when verified with a different secret.
func TestMintResourceToken_WrongSecretRejected(t *testing.T) {
	token, _ := oa.MintResourceToken("user-1", "app-1", "correct-secret", oa.AppQuota{}, []string{"read"})

	// Verify with wrong secret should fail
	_, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte("wrong-secret"), nil
	})
	if err == nil {
		t.Error("Should reject token signed with different secret")
	}
}
