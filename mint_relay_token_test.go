package oneauth_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	oa "github.com/panyam/oneauth"
)

func TestMintRelayToken_Basic(t *testing.T) {
	token, err := oa.MintRelayToken("user-123", "host-abc", "my-secret", oa.HostQuota{
		MaxRooms:   10,
		MaxMsgRate: 30.0,
	}, []string{"read", "write"})
	if err != nil {
		t.Fatalf("MintRelayToken failed: %v", err)
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
	if claims["client_id"] != "host-abc" {
		t.Errorf("Expected client_id host-abc, got %v", claims["client_id"])
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

func TestMintRelayToken_NoQuota(t *testing.T) {
	token, err := oa.MintRelayToken("user-1", "host-1", "secret", oa.HostQuota{}, []string{"read"})
	if err != nil {
		t.Fatalf("MintRelayToken failed: %v", err)
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

func TestMintRelayToken_VerifiableByMiddleware(t *testing.T) {
	secret := "shared-secret-between-host-and-relay"
	clientID := "host-excaliframe"

	// Host mints token
	token, err := oa.MintRelayToken("user-42", clientID, secret, oa.HostQuota{}, []string{"read"})
	if err != nil {
		t.Fatalf("MintRelayToken failed: %v", err)
	}

	// Relay verifies using KeyStore
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

func TestMintRelayToken_WrongSecretRejected(t *testing.T) {
	token, _ := oa.MintRelayToken("user-1", "host-1", "correct-secret", oa.HostQuota{}, []string{"read"})

	// Verify with wrong secret should fail
	_, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte("wrong-secret"), nil
	})
	if err == nil {
		t.Error("Should reject token signed with different secret")
	}
}
