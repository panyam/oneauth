package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key (RFC 7517).
// Only public key components are included — the struct intentionally omits
// private key fields (d, p, q, dp, dq, qi) so they cannot leak via JWKS.
type JWK struct {
	Kty    string   `json:"kty"`           // "RSA" or "EC"
	Kid    string   `json:"kid"`           // key identifier (RFC 7638 thumbprint)
	Alg    string   `json:"alg"`           // "RS256" or "ES256"
	Use    string   `json:"use"`           // "sig"
	KeyOps []string `json:"key_ops"`       // ["verify"] — explicit usage restriction
	N      string   `json:"n,omitempty"`   // RSA modulus (base64url, no padding)
	E      string   `json:"e,omitempty"`   // RSA exponent (base64url, no padding)
	Crv    string   `json:"crv,omitempty"` // EC curve ("P-256")
	X      string   `json:"x,omitempty"`   // EC x-coordinate (base64url, no padding)
	Y      string   `json:"y,omitempty"`   // EC y-coordinate (base64url, no padding)
}

// JWKSet represents a JSON Web Key Set (RFC 7517 Section 5).
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// PublicKeyToJWK converts a crypto.PublicKey to a JWK, dispatching by key type.
func PublicKeyToJWK(kid, alg string, pub crypto.PublicKey) (JWK, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return RSAPublicKeyToJWK(kid, alg, k), nil
	case *ecdsa.PublicKey:
		return ECDSAPublicKeyToJWK(kid, alg, k), nil
	default:
		return JWK{}, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// RSAPublicKeyToJWK converts an RSA public key to a JWK.
func RSAPublicKeyToJWK(kid, alg string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty:    "RSA",
		Kid:    kid,
		Alg:    alg,
		Use:    "sig",
		KeyOps: []string{"verify"},
		N:      base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:      base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ECDSAPublicKeyToJWK converts an ECDSA public key to a JWK.
// Uses pub.Bytes() (Go 1.25+) instead of deprecated X/Y fields.
func ECDSAPublicKeyToJWK(kid, alg string, pub *ecdsa.PublicKey) JWK {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	// pub.Bytes() returns uncompressed point: 0x04 || X || Y
	uncompressed, _ := pub.Bytes()
	xPadded := uncompressed[1 : 1+byteLen]
	yPadded := uncompressed[1+byteLen:]

	return JWK{
		Kty:    "EC",
		Kid:    kid,
		Alg:    alg,
		Use:    "sig",
		KeyOps: []string{"verify"},
		Crv:    pub.Curve.Params().Name,
		X:      base64.RawURLEncoding.EncodeToString(xPadded),
		Y:      base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

// JWKToPublicKey converts a JWK back to a crypto.PublicKey and returns the algorithm.
func JWKToPublicKey(jwk JWK) (crypto.PublicKey, string, error) {
	switch jwk.Kty {
	case "RSA":
		return rsaJWKToPublicKey(jwk)
	case "EC":
		return ecJWKToPublicKey(jwk)
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func rsaJWKToPublicKey(jwk JWK) (crypto.PublicKey, string, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode RSA exponent: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, "", fmt.Errorf("RSA exponent too large")
	}
	pub := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}
	return pub, jwk.Alg, nil
}

func ecJWKToPublicKey(jwk JWK) (crypto.PublicKey, string, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	default:
		return nil, "", fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode EC x-coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode EC y-coordinate: %w", err)
	}
	// Build uncompressed point: 0x04 || X || Y
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(xBytes) > byteLen || len(yBytes) > byteLen {
		return nil, "", fmt.Errorf("EC coordinate too large for curve %s", jwk.Crv)
	}
	uncompressed := make([]byte, 1+2*byteLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1+byteLen-len(xBytes):1+byteLen], xBytes)
	copy(uncompressed[1+2*byteLen-len(yBytes):], yBytes)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return nil, "", fmt.Errorf("invalid EC public key: %w", err)
	}
	return pub, jwk.Alg, nil
}
