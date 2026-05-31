package provisioner

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

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
