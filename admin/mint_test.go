package admin_test

// Tests for MintResourceToken: HS256 token minting, claim population,
// custom-claims pass-through, the standard-claim override guard,
// KeyStore-based verification, and rejection of tokens signed with the wrong key.

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
)

// TestMintResourceToken_Basic verifies that MintResourceToken produces a valid HS256 JWT
// with the correct sub, client_id, type, and that arbitrary customClaims round-trip.
func TestMintResourceToken_Basic(t *testing.T) {
	token, err := admin.MintResourceToken("user-123", "app-abc", []byte("my-secret"),
		map[string]any{
			"tier":         "gold",
			"feature_flag": true,
			"max_rooms":    10,
		},
		[]string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("MintResourceToken failed: %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}

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
	if claims["tier"] != "gold" {
		t.Errorf("Expected custom tier=gold, got %v", claims["tier"])
	}
	if claims["feature_flag"] != true {
		t.Errorf("Expected custom feature_flag=true, got %v", claims["feature_flag"])
	}
	if claims["max_rooms"] != float64(10) {
		t.Errorf("Expected custom max_rooms=10, got %v", claims["max_rooms"])
	}
}

// TestMintResourceToken_NoCustomClaims verifies that a nil customClaims map
// leaves only the standard claims present.
func TestMintResourceToken_NoCustomClaims(t *testing.T) {
	token, err := admin.MintResourceToken("user-1", "app-1", []byte("secret"), nil, []string{"read"}, nil)
	if err != nil {
		t.Fatalf("MintResourceToken failed: %v", err)
	}

	parsed, _ := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte("secret"), nil
	})
	claims := parsed.Claims.(jwt.MapClaims)

	for _, k := range []string{"tier", "feature_flag", "max_rooms", "max_msg_rate"} {
		if _, exists := claims[k]; exists {
			t.Errorf("expected absent claim %q when no customClaims passed; got %v", k, claims[k])
		}
	}
}

// TestMintResourceToken_StandardClaimOverrideGuard proves that customClaims
// CANNOT overwrite the JWT standard claims that MintResourceToken owns
// (sub, client_id, type, scopes, iat, exp, jti, iss, aud,
// authorization_details). Collisions are silently dropped (and logged).
//
// Red-before-green: remove the guard loop in admin/mint.go, run this test,
// confirm it fails (because user-attempted overrides would land in the JWT),
// then restore the guard and confirm it passes.
func TestMintResourceToken_StandardClaimOverrideGuard(t *testing.T) {
	token, err := admin.MintResourceToken("real-user", "real-app", []byte("k"),
		map[string]any{
			"sub":                   "attacker",
			"client_id":             "evil-app",
			"type":                  "refresh",
			"scopes":                []string{"admin"},
			"iat":                   int64(0),
			"exp":                   int64(0),
			"jti":                   "spoofed",
			"iss":                   "evil-issuer",
			"aud":                   "evil-audience",
			"authorization_details": []any{map[string]any{"type": "spoof"}},
			"tier":                  "gold", // benign custom claim must still pass through
		},
		[]string{"read"}, nil)
	if err != nil {
		t.Fatalf("MintResourceToken failed: %v", err)
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte("k"), nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	if claims["sub"] != "real-user" {
		t.Errorf("sub overridden: got %v, want real-user", claims["sub"])
	}
	if claims["client_id"] != "real-app" {
		t.Errorf("client_id overridden: got %v, want real-app", claims["client_id"])
	}
	if claims["type"] != "access" {
		t.Errorf("type overridden: got %v, want access", claims["type"])
	}
	if claims["jti"] == "spoofed" {
		t.Errorf("jti overridden: got spoofed")
	}
	if claims["iss"] == "evil-issuer" {
		t.Errorf("iss overridden: got evil-issuer")
	}
	if claims["aud"] == "evil-audience" {
		t.Errorf("aud overridden: got evil-audience")
	}
	if claims["exp"] == float64(0) {
		t.Errorf("exp overridden to 0 — token would not expire correctly")
	}
	if claims["iat"] == float64(0) {
		t.Errorf("iat overridden to 0")
	}
	// authorization_details must not be set from customClaims (the param is nil here).
	if _, present := claims["authorization_details"]; present {
		t.Errorf("authorization_details overridden via customClaims; should have come from the dedicated parameter only")
	}
	// scopes must reflect the dedicated parameter, not the override attempt.
	scopes, _ := claims["scopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "read" {
		t.Errorf("scopes overridden: got %v, want [read]", claims["scopes"])
	}
	// Benign custom claim is still merged.
	if claims["tier"] != "gold" {
		t.Errorf("benign custom claim dropped: tier=%v, want gold", claims["tier"])
	}
}

// TestMintResourceToken_VerifiableByMiddleware verifies that a minted token can be validated
// using a KeyStore-based key function, simulating the APIMiddleware verification flow.
func TestMintResourceToken_VerifiableByMiddleware(t *testing.T) {
	secret := "shared-secret-between-app-and-resource-server"
	clientID := "app-excaliframe"

	token, err := admin.MintResourceToken("user-42", clientID, []byte(secret), nil, []string{"read"}, nil)
	if err != nil {
		t.Fatalf("MintResourceToken failed: %v", err)
	}

	ks := keys.NewInMemoryKeyStore()
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: clientID, Key: []byte(secret), Algorithm: "HS256"}})
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		claims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			return nil, keys.ErrKeyNotFound
		}
		cid, _ := claims["client_id"].(string)
		resp, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: cid})
		if err != nil {
			return nil, err
		}
		if t.Header["alg"] != resp.Record.Algorithm {
			return nil, keys.ErrAlgorithmMismatch
		}
		return resp.Record.Key, nil
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
	token, _ := admin.MintResourceToken("user-1", "app-1", []byte("correct-secret"), nil, []string{"read"}, nil)

	_, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte("wrong-secret"), nil
	})
	if err == nil {
		t.Error("Should reject token signed with different secret")
	}
}
