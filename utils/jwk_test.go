package utils

// Tests for JWK conversion utilities: RSA and ECDSA public key to/from JWK format,
// round-trip fidelity, the generic PublicKeyToJWK dispatcher, and error handling
// for unsupported key types.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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

// =============================================================================
// JWKS Security Safety Proofs (#26)
//
// These tests document and verify the structural guarantees that prevent
// private key leakage and ensure spec-compliant JWKS output.
//
// References:
//   - RFC 7517 (https://datatracker.ietf.org/doc/html/rfc7517): JSON Web Key
//   - RFC 7517 §4.3 (https://datatracker.ietf.org/doc/html/rfc7517#section-4.3): key_ops
//   - RFC 7518 §6.3 (https://datatracker.ietf.org/doc/html/rfc7518#section-6.3): RSA key params
// =============================================================================

// TestJWK_RSA_NoPrivateKeyFields proves that marshalling an RSA JWK to JSON
// cannot contain RSA private key components (d, p, q, dp, dq, qi).
// This is guaranteed by the JWK struct definition which has no such fields.
func TestJWK_RSA_NoPrivateKeyFields(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk := RSAPublicKeyToJWK("test-rsa", "RS256", &priv.PublicKey)
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}

	// Parse back as raw map to check ALL fields
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	// RSA private key fields that must NEVER appear
	forbidden := []string{"d", "p", "q", "dp", "dq", "qi"}
	for _, field := range forbidden {
		if _, exists := raw[field]; exists {
			t.Errorf("SECURITY: RSA private key field %q found in JWK JSON output", field)
		}
	}

	// Verify expected public fields are present
	for _, field := range []string{"kty", "kid", "alg", "use", "key_ops", "n", "e"} {
		if _, exists := raw[field]; !exists {
			t.Errorf("expected field %q missing from JWK JSON output", field)
		}
	}
}

// TestJWK_ECDSA_NoPrivateKeyFields proves that marshalling an ECDSA JWK to JSON
// cannot contain the EC private key component (d).
func TestJWK_ECDSA_NoPrivateKeyFields(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := ECDSAPublicKeyToJWK("test-ec", "ES256", &priv.PublicKey)
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	// EC private key field that must NEVER appear
	if _, exists := raw["d"]; exists {
		t.Error("SECURITY: EC private key field \"d\" found in JWK JSON output")
	}

	// Verify expected public fields
	for _, field := range []string{"kty", "kid", "alg", "use", "key_ops", "crv", "x", "y"} {
		if _, exists := raw[field]; !exists {
			t.Errorf("expected field %q missing from JWK JSON output", field)
		}
	}
}

// TestJWK_PrivateKeyTypeRejected proves that passing a private key (not public)
// to PublicKeyToJWK is rejected — the type switch only matches *rsa.PublicKey
// and *ecdsa.PublicKey, not their private key counterparts.
func TestJWK_PrivateKeyTypeRejected(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := PublicKeyToJWK("rsa-priv", "RS256", rsaPriv) // *rsa.PrivateKey, not *rsa.PublicKey
	if err == nil {
		t.Error("SECURITY: PublicKeyToJWK should reject *rsa.PrivateKey")
	}

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = PublicKeyToJWK("ec-priv", "ES256", ecPriv) // *ecdsa.PrivateKey, not *ecdsa.PublicKey
	if err == nil {
		t.Error("SECURITY: PublicKeyToJWK should reject *ecdsa.PrivateKey")
	}
}

// TestJWK_SymmetricKeyRejected proves that symmetric (HS256) keys cannot be
// converted to JWK — they are shared secrets and must never appear in JWKS.
func TestJWK_SymmetricKeyRejected(t *testing.T) {
	_, err := PublicKeyToJWK("hmac", "HS256", []byte("my-secret"))
	if err == nil {
		t.Error("SECURITY: PublicKeyToJWK should reject symmetric []byte keys")
	}
}

// TestJWK_KeyOpsVerifyOnly verifies that all JWK entries include
// key_ops: ["verify"] per RFC 7517 Section 4.3, restricting usage to
// signature verification only.
func TestJWK_KeyOpsVerifyOnly(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaJWK := RSAPublicKeyToJWK("rsa", "RS256", &rsaPriv.PublicKey)
	if len(rsaJWK.KeyOps) != 1 || rsaJWK.KeyOps[0] != "verify" {
		t.Errorf("RSA JWK key_ops = %v, want [\"verify\"]", rsaJWK.KeyOps)
	}

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecJWK := ECDSAPublicKeyToJWK("ec", "ES256", &ecPriv.PublicKey)
	if len(ecJWK.KeyOps) != 1 || ecJWK.KeyOps[0] != "verify" {
		t.Errorf("EC JWK key_ops = %v, want [\"verify\"]", ecJWK.KeyOps)
	}
}
