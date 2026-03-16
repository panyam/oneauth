package utils_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/panyam/oneauth/utils"
)

func TestGenerateRSAKeyPair(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}
	if len(privPEM) == 0 || len(pubPEM) == 0 {
		t.Fatal("Expected non-empty PEM output")
	}
}

func TestGenerateECDSAKeyPair(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair failed: %v", err)
	}
	if len(privPEM) == 0 || len(pubPEM) == 0 {
		t.Fatal("Expected non-empty PEM output")
	}
}

func TestRSA_RoundTrip(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	priv, err := utils.ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM failed: %v", err)
	}
	if _, ok := priv.(*rsa.PrivateKey); !ok {
		t.Fatalf("Expected *rsa.PrivateKey, got %T", priv)
	}

	pub, err := utils.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM failed: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("Expected *rsa.PublicKey, got %T", pub)
	}

	// Re-encode and compare
	reEncoded, err := utils.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("EncodePublicKeyPEM failed: %v", err)
	}
	if string(reEncoded) != string(pubPEM) {
		t.Error("Re-encoded public key PEM should match original")
	}
}

func TestECDSA_RoundTrip(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair failed: %v", err)
	}

	priv, err := utils.ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM failed: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", priv)
	}

	pub, err := utils.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM failed: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("Expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestDecodeVerifyKey_HMAC_Passthrough(t *testing.T) {
	secret := []byte("my-secret")
	key, err := utils.DecodeVerifyKey(secret, "HS256")
	if err != nil {
		t.Fatalf("DecodeVerifyKey HS256 failed: %v", err)
	}
	if string(key.([]byte)) != "my-secret" {
		t.Error("HMAC key should pass through unchanged")
	}
}

func TestDecodeVerifyKey_RS256_FromPEM(t *testing.T) {
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)

	key, err := utils.DecodeVerifyKey(pubPEM, "RS256")
	if err != nil {
		t.Fatalf("DecodeVerifyKey RS256 failed: %v", err)
	}
	if _, ok := key.(*rsa.PublicKey); !ok {
		t.Fatalf("Expected *rsa.PublicKey, got %T", key)
	}
}

func TestDecodeVerifyKey_ES256_FromPEM(t *testing.T) {
	_, pubPEM, _ := utils.GenerateECDSAKeyPair()

	key, err := utils.DecodeVerifyKey(pubPEM, "ES256")
	if err != nil {
		t.Fatalf("DecodeVerifyKey ES256 failed: %v", err)
	}
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Fatalf("Expected *ecdsa.PublicKey, got %T", key)
	}
}

func TestDecodeVerifyKey_RS256_AlreadyParsed(t *testing.T) {
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	pub, _ := utils.ParsePublicKeyPEM(pubPEM)

	key, err := utils.DecodeVerifyKey(pub, "RS256")
	if err != nil {
		t.Fatalf("DecodeVerifyKey RS256 (parsed) failed: %v", err)
	}
	if key != pub {
		t.Error("Already-parsed key should be returned as-is")
	}
}

func TestDecodeVerifyKey_ES256_AlreadyParsed(t *testing.T) {
	_, pubPEM, _ := utils.GenerateECDSAKeyPair()
	pub, _ := utils.ParsePublicKeyPEM(pubPEM)

	key, err := utils.DecodeVerifyKey(pub, "ES256")
	if err != nil {
		t.Fatalf("DecodeVerifyKey ES256 (parsed) failed: %v", err)
	}
	if key != pub {
		t.Error("Already-parsed key should be returned as-is")
	}
}

func TestDecodeVerifyKey_RS256_WrongKeyType(t *testing.T) {
	_, pubPEM, _ := utils.GenerateECDSAKeyPair() // ECDSA, not RSA

	_, err := utils.DecodeVerifyKey(pubPEM, "RS256")
	if err == nil {
		t.Fatal("Expected error when ECDSA PEM used with RS256")
	}
}

func TestDecodeVerifyKey_InvalidPEM(t *testing.T) {
	_, err := utils.DecodeVerifyKey([]byte("not-a-pem"), "RS256")
	if err == nil {
		t.Fatal("Expected error for invalid PEM")
	}
}

func TestIsAsymmetricAlg(t *testing.T) {
	if !utils.IsAsymmetricAlg("RS256") {
		t.Error("RS256 should be asymmetric")
	}
	if !utils.IsAsymmetricAlg("ES256") {
		t.Error("ES256 should be asymmetric")
	}
	if utils.IsAsymmetricAlg("HS256") {
		t.Error("HS256 should not be asymmetric")
	}
}

func TestSigningMethodForAlg(t *testing.T) {
	tests := map[string]string{
		"HS256": "HS256",
		"HS384": "HS384",
		"HS512": "HS512",
		"RS256": "RS256",
		"ES256": "ES256",
		"":      "HS256", // default
	}
	for input, expected := range tests {
		m := utils.SigningMethodForAlg(input)
		if m.Alg() != expected {
			t.Errorf("SigningMethodForAlg(%q) = %s, want %s", input, m.Alg(), expected)
		}
	}
}

func TestParsePublicKeyPEM_InvalidBlock(t *testing.T) {
	_, err := utils.ParsePublicKeyPEM([]byte("garbage"))
	if err == nil {
		t.Fatal("Expected error for garbage input")
	}
}

func TestParsePrivateKeyPEM_InvalidBlock(t *testing.T) {
	_, err := utils.ParsePrivateKeyPEM([]byte("garbage"))
	if err == nil {
		t.Fatal("Expected error for garbage input")
	}
}
