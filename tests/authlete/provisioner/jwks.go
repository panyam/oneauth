package provisioner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// generateJWKSetForAlg dispatches to the appropriate key-type generator
// based on alg's RFC 7518 family:
//
//   - RS256 / RS384 / RS512 → RSA-2048 (a single RSA key serves all three
//     RS variants; only the hash algorithm differs at sign-time).
//   - ES256 → ECDSA P-256
//   - ES384 → ECDSA P-384
//   - ES512 → ECDSA P-521 (note: 521, not 512 — RFC 7518 §3.4)
//
// Returns the JWK Set as a JSON string suitable for Authlete's
// `service.jwks` field, plus the kid embedded in the key so the caller
// can verify token headers later.
func generateJWKSetForAlg(kid, alg string) (jwksJSON string, err error) {
	switch alg {
	case "RS256", "RS384", "RS512":
		jwksJSON, _, err = generateRSAJWKSet(kid, alg)
		return
	case "ES256":
		return generateECDSAJWKSet(kid, alg, elliptic.P256())
	case "ES384":
		return generateECDSAJWKSet(kid, alg, elliptic.P384())
	case "ES512":
		return generateECDSAJWKSet(kid, alg, elliptic.P521())
	default:
		return "", fmt.Errorf("unsupported alg for JWKS generation: %q (want RS256/384/512 or ES256/384/512)", alg)
	}
}

// generateECDSAJWKSet produces a JWK Set JSON string containing a single
// freshly-generated ECDSA private key on the requested curve. Authlete
// needs the PRIVATE key parameter (d) so it can sign tokens; the
// existing utils.ECDSAPublicKeyToJWK only emits public coordinates.
func generateECDSAJWKSet(kid, alg string, curve elliptic.Curve) (string, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ECDSA key on %s: %w", curve.Params().Name, err)
	}
	jwk := ecdsaPrivateKeyToJWK(kid, alg, priv)
	set := map[string]any{"keys": []any{jwk}}
	buf, err := json.Marshal(set)
	if err != nil {
		return "", fmt.Errorf("marshal JWK set: %w", err)
	}
	return string(buf), nil
}

// ecdsaPrivateKeyToJWK serializes an ECDSA private key to its RFC 7518
// JWK form. The "crv" value is the JWK-spec curve name (P-256 / P-384 /
// P-521), not Authlete's alg name. x/y/d are fixed-width per the curve
// (RFC 7518 §6.2.1.2).
//
// Uses ecdsa.PrivateKey.Bytes() and PublicKey.Bytes() rather than the
// deprecated direct .X/.Y/.D access — these accessors return SEC1-
// encoded byte slices with the spec-mandated fixed width baked in (no
// manual zero-padding needed).
func ecdsaPrivateKeyToJWK(kid, alg string, priv *ecdsa.PrivateKey) map[string]any {
	// priv.Bytes() returns the raw private scalar at curve.byteSize.
	dBytes, _ := priv.Bytes()
	// priv.PublicKey.Bytes() returns SEC1 uncompressed: 0x04 || X || Y,
	// with X and Y each at curve.byteSize. Split into halves.
	pubBytes, _ := priv.PublicKey.Bytes()
	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	// pubBytes layout: [0x04][X (byteLen bytes)][Y (byteLen bytes)]
	xBytes := pubBytes[1 : 1+byteLen]
	yBytes := pubBytes[1+byteLen:]

	return map[string]any{
		"kty": "EC",
		"use": "sig",
		"alg": alg,
		"kid": kid,
		"crv": priv.Curve.Params().Name,
		"x":   b64u(xBytes),
		"y":   b64u(yBytes),
		"d":   b64u(dBytes),
	}
}

// _ keeps math/big imported for the RSA path (which references it via
// the big.Int type on rsa.PrivateKey fields).
var _ = big.NewInt

// generateRSAJWKSet produces a JWK Set JSON string containing a single
// freshly-generated RSA-2048 private key suitable for Authlete's `jwks`
// service field. Authlete needs the PRIVATE key parameters (d, p, q,
// dp, dq, qi) so it can sign tokens — the existing utils.RSAPublicKeyToJWK
// only emits the public half. The returned string is what Authlete's
// service.update API expects: a JSON document with a top-level "keys"
// array containing one JWK object.
//
// alg is one of RS256/RS384/RS512 (controls the alg claim on each key);
// kid is the key identifier embedded in tokens' JWT headers and exposed
// via the JWKS endpoint.
func generateRSAJWKSet(kid, alg string) (string, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("generate RSA key: %w", err)
	}
	jwk := rsaPrivateKeyToJWK(kid, alg, priv)
	set := map[string]any{"keys": []any{jwk}}
	buf, err := json.Marshal(set)
	if err != nil {
		return "", nil, fmt.Errorf("marshal JWK set: %w", err)
	}
	return string(buf), priv, nil
}

// rsaPrivateKeyToJWK serializes an RSA private key to its RFC 7518 JWK
// representation. All numeric components are base64url-encoded with no
// padding, per RFC 7515 §2.
func rsaPrivateKeyToJWK(kid, alg string, priv *rsa.PrivateKey) map[string]any {
	priv.Precompute() // ensure Dp/Dq/Qinv are populated for the JWK output
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": alg,
		"kid": kid,
		"n":   b64u(priv.N.Bytes()),
		"e":   b64u(big2b(int64(priv.E))),
		"d":   b64u(priv.D.Bytes()),
		"p":   b64u(priv.Primes[0].Bytes()),
		"q":   b64u(priv.Primes[1].Bytes()),
		"dp":  b64u(priv.Precomputed.Dp.Bytes()),
		"dq":  b64u(priv.Precomputed.Dq.Bytes()),
		"qi":  b64u(priv.Precomputed.Qinv.Bytes()),
	}
}

func b64u(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// big2b emits the minimal big-endian byte representation of a positive
// int64. RSA's public exponent E (usually 65537) needs to be encoded
// without leading zeros per the JWK spec.
func big2b(n int64) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return b
}
