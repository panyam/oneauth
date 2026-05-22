// Package utils provides crypto and encoding helpers — PEM/PKCS8 key
// generation and parsing, JWK/JWKS conversion, RFC 7638 kid thumbprints,
// JWT signing-method lookup, and Flask session-cookie decoding.
//
// <!-- design:start -->
// This package is a leaf bag of stateless helpers shared across OneAuth. It
// owns three loosely related concerns. First, asymmetric key plumbing:
// generating RSA (NIST-floored at MinRSAKeySize=2048) and ECDSA P-256 key
// pairs, and encoding/parsing them as PKIX public PEM and PKCS8 private PEM.
// Second, JWK handling per RFC 7517/7638: converting public keys to and from
// JWK structs (public components only, never private fields), and computing
// deterministic key IDs as RFC 7638 thumbprints for asymmetric keys or a
// SHA-256 base64url hash for HMAC secrets. Third, a self-contained Flask
// session-cookie decoder for interop with a Python backend. It does not
// store keys, manage rotation, or sign/verify tokens — callers own those.
//
// A few cross-cutting rules: IsAsymmetricAlg is the single gate deciding
// whether key material is PEM-parsed (RS256/ES256) or passed through raw
// (HMAC). DecodeVerifyKey is idempotent — already-typed keys pass straight
// back — and SigningMethodForAlg errors on unknown algorithms rather than
// silently defaulting to HS256 (empty string is the one allowed HS256 alias).
// ECDSA encoding uses pub.Bytes() (Go 1.25+) with explicit zero-padding to
// the curve coordinate length, and JWKToPublicKey validates exponent and
// coordinate sizes so malformed input errors instead of yielding bad keys.
//
// # ENTITIES
//
// MinRSAKeySize — minimum RSA size in bits (2048), enforcing the NIST SP
// 800-57 floor.
//
// GenerateRSAKeyPair — generates an RSA pair as PEM bytes, rejecting sizes
// below MinRSAKeySize.
//
// GenerateECDSAKeyPair — generates an ECDSA P-256 pair as PEM bytes
// (P-256 is the only curve the JWK path supports).
//
// ParsePublicKeyPEM — parses a PKIX public-key PEM into a crypto.PublicKey.
//
// ParsePrivateKeyPEM — parses a PKCS8 private-key PEM (PKCS1/SEC1 not
// supported).
//
// EncodePublicKeyPEM — encodes a crypto.PublicKey as PKIX "PUBLIC KEY" PEM.
//
// EncodePrivateKeyPEM — encodes a crypto.PrivateKey as PKCS8 "PRIVATE KEY"
// PEM so one parser handles RSA and ECDSA.
//
// DecodeVerifyKey — normalizes raw KeyStore material into the JWT verify
// key type for an alg; HMAC passes through, RS256/ES256 PEM-parse, already
// typed keys are returned as-is.
//
// IsAsymmetricAlg — reports whether an alg is RS256/ES256; the gate between
// PEM-parse and raw-bytes branches.
//
// SigningMethodForAlg — maps an alg string to a jwt.SigningMethod, erroring
// on unknown algs; empty string means HS256.
//
// JWK — RFC 7517 JSON Web Key holding only public components, omitting
// private fields so they cannot leak via JWKS.
//
// JWKSet — RFC 7517 §5 wrapper for a list of JWKs.
//
// PublicKeyToJWK — converts any crypto.PublicKey to a JWK, dispatching on
// type and erroring on unsupported keys.
//
// RSAPublicKeyToJWK — builds an RSA JWK with use=sig and key_ops=[verify].
//
// ECDSAPublicKeyToJWK — builds an EC JWK using pub.Bytes() (Go 1.25+) with
// zero-padded coordinates, use=sig, key_ops=[verify].
//
// JWKToPublicKey — reconstructs a crypto.PublicKey and alg from a JWK,
// validating exponent/coordinate sizes.
//
// ComputeKid — computes a deterministic 43-char kid: RFC 7638 thumbprint
// for asymmetric keys, SHA-256 for HMAC; []byte under an asymmetric alg is
// parsed to take the thumbprint path.
//
// StrMap — alias for map[string]any used for decoded Flask payloads.
//
// FlaskAuth — decodes and verifies Flask session cookies from an app secret;
// LogCookies gates verbose debug logging.
//
// FlaskAuth.NormalizedSecretKey — pads/truncates the secret to 32 bytes and
// base64-encodes it as a Fernet key, mirroring Flask's derivation quirk.
//
// FlaskAuth.DecodeSessionCookie — decodes a base64 cookie body (optionally
// zlib-decompressed when prefixed with '.') into a StrMap.
//
// FlaskAuth.DecodeSessionUserId — Fernet-decrypts a user ID into '|'-split
// parts; '~'-prefixed parts are excel-base-decoded to numbers.
//
// FlaskAuth.ParseSignedCookieValue — composes the two decoders to extract
// _user_id parts plus the full session map.
// <!-- design:end -->
package utils
