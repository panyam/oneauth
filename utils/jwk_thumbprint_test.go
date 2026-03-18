package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestComputeKid_HMAC_Deterministic(t *testing.T) {
	secret := []byte("my-shared-secret")
	kid1, err := ComputeKid(secret, "HS256")
	if err != nil {
		t.Fatal(err)
	}
	kid2, err := ComputeKid(secret, "HS256")
	if err != nil {
		t.Fatal(err)
	}
	if kid1 != kid2 {
		t.Errorf("same key should produce same kid: %s != %s", kid1, kid2)
	}
	if len(kid1) != 43 {
		t.Errorf("kid should be 43 chars (base64url of SHA-256), got %d", len(kid1))
	}
}

func TestComputeKid_HMAC_DifferentKeys(t *testing.T) {
	kid1, _ := ComputeKid([]byte("secret-a"), "HS256")
	kid2, _ := ComputeKid([]byte("secret-b"), "HS256")
	if kid1 == kid2 {
		t.Error("different keys should produce different kids")
	}
}

func TestComputeKid_RSA_Deterministic(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid1, err := ComputeKid(&key.PublicKey, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	kid2, err := ComputeKid(&key.PublicKey, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	if kid1 != kid2 {
		t.Errorf("same RSA key should produce same kid: %s != %s", kid1, kid2)
	}
	if len(kid1) != 43 {
		t.Errorf("kid should be 43 chars, got %d", len(kid1))
	}
}

func TestComputeKid_RSA_PrivateAndPublicMatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kidPriv, _ := ComputeKid(key, "RS256")
	kidPub, _ := ComputeKid(&key.PublicKey, "RS256")
	if kidPriv != kidPub {
		t.Errorf("private and public RSA key should produce same kid: %s != %s", kidPriv, kidPub)
	}
}

func TestComputeKid_RSA_DifferentKeys(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid1, _ := ComputeKid(&key1.PublicKey, "RS256")
	kid2, _ := ComputeKid(&key2.PublicKey, "RS256")
	if kid1 == kid2 {
		t.Error("different RSA keys should produce different kids")
	}
}

func TestComputeKid_ECDSA_Deterministic(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid1, _ := ComputeKid(&key.PublicKey, "ES256")
	kid2, _ := ComputeKid(&key.PublicKey, "ES256")
	if kid1 != kid2 {
		t.Errorf("same EC key should produce same kid: %s != %s", kid1, kid2)
	}
	if len(kid1) != 43 {
		t.Errorf("kid should be 43 chars, got %d", len(kid1))
	}
}

func TestComputeKid_ECDSA_PrivateAndPublicMatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kidPriv, _ := ComputeKid(key, "ES256")
	kidPub, _ := ComputeKid(&key.PublicKey, "ES256")
	if kidPriv != kidPub {
		t.Errorf("private and public EC key should produce same kid: %s != %s", kidPriv, kidPub)
	}
}

func TestComputeKid_ECDSA_DifferentKeys(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid1, _ := ComputeKid(&key1.PublicKey, "ES256")
	kid2, _ := ComputeKid(&key2.PublicKey, "ES256")
	if kid1 == kid2 {
		t.Error("different EC keys should produce different kids")
	}
}

func TestComputeKid_UnsupportedType(t *testing.T) {
	_, err := ComputeKid("not-a-key", "HS256")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}
