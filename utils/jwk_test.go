package utils

// Tests for JWK conversion utilities: RSA and ECDSA public key to/from JWK format,
// round-trip fidelity, the generic PublicKeyToJWK dispatcher, and error handling
// for unsupported key types.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TestRSAPublicKeyToJWK verifies that an RSA public key is correctly converted to a JWK
// with the expected kty, kid, alg, use, N, and E fields.
func TestRSAPublicKeyToJWK(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := RSAPublicKeyToJWK("app_rsa1", "RS256", &priv.PublicKey)

	if jwk.Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %s", jwk.Kty)
	}
	if jwk.Kid != "app_rsa1" {
		t.Errorf("expected kid=app_rsa1, got %s", jwk.Kid)
	}
	if jwk.Alg != "RS256" {
		t.Errorf("expected alg=RS256, got %s", jwk.Alg)
	}
	if jwk.Use != "sig" {
		t.Errorf("expected use=sig, got %s", jwk.Use)
	}
	if jwk.N == "" || jwk.E == "" {
		t.Error("N and E must not be empty")
	}
}

// TestECDSAPublicKeyToJWK verifies that an ECDSA P-256 public key is correctly converted
// to a JWK with the expected kty, kid, alg, use, crv, X, and Y fields.
func TestECDSAPublicKeyToJWK(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := ECDSAPublicKeyToJWK("app_ec1", "ES256", &priv.PublicKey)

	if jwk.Kty != "EC" {
		t.Errorf("expected kty=EC, got %s", jwk.Kty)
	}
	if jwk.Kid != "app_ec1" {
		t.Errorf("expected kid=app_ec1, got %s", jwk.Kid)
	}
	if jwk.Alg != "ES256" {
		t.Errorf("expected alg=ES256, got %s", jwk.Alg)
	}
	if jwk.Use != "sig" {
		t.Errorf("expected use=sig, got %s", jwk.Use)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("expected crv=P-256, got %s", jwk.Crv)
	}
	if jwk.X == "" || jwk.Y == "" {
		t.Error("X and Y must not be empty")
	}
}

// TestRSARoundTrip verifies that an RSA public key survives conversion to JWK and back
// with matching modulus and exponent.
func TestRSARoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	orig := &priv.PublicKey

	jwk := RSAPublicKeyToJWK("rsa_rt", "RS256", orig)
	pub, alg, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "RS256" {
		t.Errorf("expected alg RS256, got %s", alg)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
	if orig.N.Cmp(rsaPub.N) != 0 {
		t.Error("RSA modulus mismatch after round-trip")
	}
	if orig.E != rsaPub.E {
		t.Error("RSA exponent mismatch after round-trip")
	}
}

// TestECDSARoundTrip verifies that an ECDSA public key survives conversion to JWK and back
// with matching X and Y coordinates.
func TestECDSARoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := &priv.PublicKey

	jwk := ECDSAPublicKeyToJWK("ec_rt", "ES256", orig)
	pub, alg, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "ES256" {
		t.Errorf("expected alg ES256, got %s", alg)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if orig.X.Cmp(ecPub.X) != 0 || orig.Y.Cmp(ecPub.Y) != 0 {
		t.Error("ECDSA coordinates mismatch after round-trip")
	}
}

// TestPublicKeyToJWK_RSA verifies that the generic PublicKeyToJWK dispatches correctly for RSA keys.
func TestPublicKeyToJWK_RSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk, err := PublicKeyToJWK("kid1", "RS256", &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %s", jwk.Kty)
	}
}

// TestPublicKeyToJWK_ECDSA verifies that the generic PublicKeyToJWK dispatches correctly for ECDSA keys.
func TestPublicKeyToJWK_ECDSA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, err := PublicKeyToJWK("kid2", "ES256", &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kty != "EC" {
		t.Errorf("expected kty=EC, got %s", jwk.Kty)
	}
}

// TestPublicKeyToJWK_UnsupportedType verifies that PublicKeyToJWK returns an error
// for non-RSA/ECDSA key types (e.g., byte slices).
func TestPublicKeyToJWK_UnsupportedType(t *testing.T) {
	_, err := PublicKeyToJWK("kid3", "HS256", []byte("secret"))
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// TestJWKToPublicKey_UnsupportedKty verifies that JWKToPublicKey returns an error
// for unsupported key types like "oct" (symmetric).
func TestJWKToPublicKey_UnsupportedKty(t *testing.T) {
	jwk := JWK{Kty: "oct", Kid: "hmac1", Alg: "HS256"}
	_, _, err := JWKToPublicKey(jwk)
	if err == nil {
		t.Error("expected error for unsupported kty")
	}
}
