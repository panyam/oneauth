package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ComputeKid computes a deterministic key ID (kid) for JWT headers.
// For asymmetric keys, this implements RFC 7638 JWK Thumbprint.
// For HMAC keys ([]byte), it returns SHA-256 of the raw bytes, base64url-encoded.
// The result is always 43 characters (256-bit hash, base64url, no padding).
//
// Supported key types:
//   - []byte: SHA-256 of raw bytes (HS256/HS384/HS512)
//   - *rsa.PublicKey or *rsa.PrivateKey: RFC 7638 thumbprint with {"e","kty","n"}
//   - *ecdsa.PublicKey or *ecdsa.PrivateKey: RFC 7638 thumbprint with {"crv","kty","x","y"}
func ComputeKid(key any, alg string) (string, error) {
	switch k := key.(type) {
	case []byte:
		// For asymmetric algorithms, try to parse PEM to compute RFC 7638 thumbprint
		if IsAsymmetricAlg(alg) {
			if pub, err := DecodeVerifyKey(k, alg); err == nil {
				return ComputeKid(pub, alg)
			}
		}
		return hashToKid(k), nil
	case *rsa.PublicKey:
		return rsaThumbprint(k)
	case *rsa.PrivateKey:
		return rsaThumbprint(&k.PublicKey)
	case *ecdsa.PublicKey:
		return ecdsaThumbprint(k)
	case *ecdsa.PrivateKey:
		return ecdsaThumbprint(&k.PublicKey)
	default:
		return "", fmt.Errorf("unsupported key type for kid computation: %T", key)
	}
}

// hashToKid computes SHA-256 of data and returns base64url (no padding).
func hashToKid(data []byte) string {
	h := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// rsaThumbprint computes the RFC 7638 JWK Thumbprint for an RSA public key.
// Canonical JSON: {"e":"...","kty":"RSA","n":"..."}
func rsaThumbprint(pub *rsa.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("nil RSA public key")
	}
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	// RFC 7638: members in lexicographic order
	canonical := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)
	return hashToKid([]byte(canonical)), nil
}

// ecdsaThumbprint computes the RFC 7638 JWK Thumbprint for an ECDSA public key.
// Canonical JSON: {"crv":"...","kty":"EC","x":"...","y":"..."}
func ecdsaThumbprint(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("nil ECDSA public key")
	}
	crv := pub.Curve.Params().Name
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)
	x := base64.RawURLEncoding.EncodeToString(xPadded)
	y := base64.RawURLEncoding.EncodeToString(yPadded)
	// RFC 7638: members in lexicographic order
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, crv, x, y)
	return hashToKid([]byte(canonical)), nil
}
