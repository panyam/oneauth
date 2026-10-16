package utils

// RSA keys below 2048 bits are refused wherever a key enters: a PEM public
// key, a PEM private key, or a JWK fetched from a remote JWKS.
//
// See: https://www.rfc-editor.org/rfc/rfc7518#section-3.3
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
// See: https://cwe.mitre.org/data/definitions/326.html

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func TestRSAKeySize_ShortKeysAreRefusedOnLoad(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := EncodePublicKeyPEM(&short.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := EncodePrivateKeyPEM(short)
	if err != nil {
		t.Fatal(err)
	}
	jwk := JWK{Kty: "RSA", Alg: "RS256", N: base64.RawURLEncoding.EncodeToString(short.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(short.E)).Bytes())}

	if _, err := ParsePublicKeyPEM(pubPEM); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("1024-bit public PEM: got %v, want a key-size error", err)
	}
	if _, err := ParsePrivateKeyPEM(privPEM); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("1024-bit private PEM: got %v, want a key-size error", err)
	}
	if _, _, err := JWKToPublicKey(jwk); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("1024-bit JWK: got %v, want a key-size error", err)
	}

	_, pub2048, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKeyPEM(pub2048); err != nil {
		t.Errorf("2048-bit key refused: %v", err)
	}
}
