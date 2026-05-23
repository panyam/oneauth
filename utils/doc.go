// Package utils provides stateless crypto and encoding helpers —
// RSA/ECDSA key generation, PEM/PKCS8 codec, JWK/JWKS conversion,
// RFC 7638 kid thumbprints, JWT signing-method lookup, and Flask
// session-cookie decoding.
//
// This package is a leaf bag of helpers shared across OneAuth and owns
// three loosely related concerns. First, asymmetric key plumbing:
// generating RSA (NIST-floored at MinRSAKeySize=2048) and ECDSA P-256
// key pairs, and encoding/parsing them as PKIX public PEM and PKCS8
// private PEM. Second, JWK handling per RFC 7517/7638: converting
// public keys to and from JWK structs (public components only, never
// private fields), and computing deterministic key IDs as RFC 7638
// thumbprints for asymmetric keys or a SHA-256 base64url hash for HMAC
// secrets. Third, a self-contained Flask session-cookie decoder for
// interop with a Python backend. The package does not store keys,
// manage rotation, or sign/verify tokens — callers own those. A few
// cross-cutting rules: IsAsymmetricAlg is the single gate deciding
// whether key material is PEM-parsed (RS256/ES256) or passed through
// raw (HMAC); DecodeVerifyKey is idempotent so already-typed keys pass
// straight back; SigningMethodForAlg errors on unknown algorithms
// rather than silently defaulting to HS256 (empty string is the one
// allowed HS256 alias); ECDSA encoding uses pub.Bytes() (Go 1.25+)
// with explicit zero-padding to the curve coordinate length; and
// JWKToPublicKey validates exponent and coordinate sizes so malformed
// input errors instead of yielding bad keys.
//
// ENTITIES
//
// MinRSAKeySize — minimum RSA size in bits (2048). Enforces the NIST
// SP 800-57 floor at generation time.
//
// GenerateRSAKeyPair — generates an RSA pair as PEM bytes. Single
// entry point that pairs key generation with the MinRSAKeySize floor.
//
// GenerateECDSAKeyPair — generates an ECDSA P-256 pair as PEM bytes.
// P-256 is the only curve the JWK path supports, so the helper
// hardcodes it.
//
// ParsePublicKeyPEM — parses a PKIX public-key PEM into a
// crypto.PublicKey. One parser handles RSA and ECDSA via PKIX
// SubjectPublicKeyInfo.
//
// ParsePrivateKeyPEM — parses a PKCS8 private-key PEM into a
// crypto.PrivateKey. PKCS8 is the only supported format so callers
// cannot accidentally feed PKCS1/SEC1.
//
// EncodePublicKeyPEM — encodes a crypto.PublicKey as PKIX
// "PUBLIC KEY" PEM. Mirror of ParsePublicKeyPEM so round-trips are
// symmetric.
//
// EncodePrivateKeyPEM — encodes a crypto.PrivateKey as PKCS8
// "PRIVATE KEY" PEM. PKCS8 lets one parser handle both RSA and ECDSA.
//
// DecodeVerifyKey — normalizes raw key material into the JWT
// verify-key type for an alg. HMAC passes through, RS256/ES256
// PEM-parse, already-typed keys are returned as-is — idempotent so
// callers can pre-parse.
//
// IsAsymmetricAlg — reports whether an alg is RS256 or ES256. The
// single gate between PEM-parse and raw-bytes branches throughout the
// package.
//
// SigningMethodForAlg — maps an alg string to a jwt.SigningMethod.
// Errors on unknown algs instead of silently defaulting to HS256;
// empty string is the one allowed HS256 alias.
//
// JWK — RFC 7517 JSON Web Key holding only public components.
// Private fields (d, p, q, dp, dq, qi) are intentionally omitted so
// they cannot leak via JWKS.
//
// JWKSet — RFC 7517 §5 wrapper for a list of JWKs. Standard JWKS
// endpoint payload shape.
//
// PublicKeyToJWK — converts any crypto.PublicKey to a JWK. Dispatches
// on key type and errors on unsupported keys so JWKS publishers get a
// single call.
//
// RSAPublicKeyToJWK — builds an RSA JWK with use=sig and
// key_ops=[verify]. Restricts the published key to verification to
// discourage misuse.
//
// ECDSAPublicKeyToJWK — builds an EC JWK with zero-padded x/y
// coordinates. Uses pub.Bytes() (Go 1.25+) and pads to the curve
// coordinate length so JWKs are byte-stable.
//
// JWKToPublicKey — reconstructs a crypto.PublicKey and alg from a
// JWK. Validates exponent and coordinate sizes so malformed JWKs error
// instead of yielding bad keys.
//
// ComputeKid — computes a deterministic 43-char kid for a key. RFC
// 7638 thumbprint for asymmetric keys, SHA-256 base64url for HMAC;
// []byte under an asymmetric alg is parsed to take the thumbprint
// path.
//
// StrMap — alias for map[string]any used for decoded Flask payloads.
// Shorthand so cookie code does not repeat the long type.
//
// FlaskAuth — decodes and verifies Flask session cookies from an app
// secret. Self-contained interop with a Python Flask backend;
// LogCookies gates verbose debug logging.
//
// FlaskAuth.NormalizedSecretKey — pads or truncates the secret to 32
// bytes and base64-encodes it as a Fernet key. Mirrors Flask's
// derivation quirk so cookies signed there decode here.
//
// FlaskAuth.DecodeSessionCookie — decodes a base64 cookie body into a
// StrMap. Handles the optional '.' prefix that signals zlib-compressed
// payloads.
//
// FlaskAuth.DecodeSessionUserId — Fernet-decrypts a user ID into
// '|'-split parts. '~'-prefixed parts are excel-base-decoded to
// numbers, matching the Flask convention.
//
// FlaskAuth.ParseSignedCookieValue — extracts _user_id parts plus the
// full session map from a signed cookie. Composes DecodeSessionCookie
// and DecodeSessionUserId so callers get both halves in one call.
package utils
