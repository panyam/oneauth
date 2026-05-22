---
package: utils
purpose: Crypto and encoding helpers for OneAuth — keypair generation, PEM parsing, JWK/JWKS conversion, RFC 7638 thumbprint kid derivation, and Flask session-cookie interop.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: GenerateRSAKeyPair
    kind: func
    role: Generates an RSA keypair, returning PKCS8 private and PKIX public PEM bytes.
    why: Hard-rejects sub-2048-bit keys (MinRSAKeySize) per NIST SP 800-57 so weak keys can't enter the system at the source.
  - name: GenerateECDSAKeyPair
    kind: func
    role: Generates a P-256 ECDSA keypair as PEM bytes.
    why: Curve is fixed to P-256, matching the only EC curve the JWK/thumbprint paths support — avoids minting keys the rest of the package can't handle.
  - name: MinRSAKeySize
    kind: const
    role: Minimum allowed RSA key size in bits (2048).
    why: Encodes the NIST SP 800-57 floor as a single named constant rather than a magic number scattered across callers.
  - name: ParsePublicKeyPEM
    kind: func
    role: Decodes a PKIX PEM block into a crypto.PublicKey.
    why: PKIX/PKCS8 is the canonical interchange format chosen so RSA and ECDSA share one parse path.
  - name: ParsePrivateKeyPEM
    kind: func
    role: Decodes a PKCS8 PEM block into a crypto.PrivateKey.
    why: PKCS8-only (not PKCS1) so a single decoder covers both key families; legacy PKCS1 input will fail loudly.
  - name: EncodePublicKeyPEM
    kind: func
    role: Marshals a crypto.PublicKey to PKIX PEM.
    why: Pairs with ParsePublicKeyPEM to keep the on-disk format consistent across generation and round-trips.
  - name: EncodePrivateKeyPEM
    kind: func
    role: Marshals a crypto.PrivateKey to PKCS8 PEM.
    why: PKCS8 chosen so the encode side matches the PKCS8-only parser.
  - name: DecodeVerifyKey
    kind: func
    role: Normalizes raw KeyStore key material into the concrete type a JWT verifier expects, dispatching on alg.
    why: Accepts both already-parsed key objects and PEM []byte so callers don't pre-parse; HMAC keys pass through untouched since they're verified as raw bytes.
  - name: IsAsymmetricAlg
    kind: func
    role: Reports whether an alg string uses asymmetric keys (RS256/ES256).
    why: Single predicate so the asymmetric-vs-HMAC branch logic isn't duplicated and can't drift between callers.
  - name: SigningMethodForAlg
    kind: func
    role: Maps an alg string to a jwt.SigningMethod.
    why: Returns an error for unknown algs rather than silently defaulting to HS256 — prevents an attacker-influenced alg from downgrading to a weaker method; empty string deliberately means HS256 for single-tenant defaults.
  - name: JWK
    kind: struct
    role: RFC 7517 JSON Web Key holding only public-key components.
    why: Intentionally omits all private fields (d, p, q, dp, dq, qi) so private material physically cannot leak through a JWKS response; KeyOps is pinned to ["verify"] to advertise usage restriction.
  - name: JWKSet
    kind: struct
    role: RFC 7517 Section 5 key set wrapper.
    why: Thin {keys:[]} envelope kept as a named type so JWKS handlers serialize a stable shape.
  - name: PublicKeyToJWK
    kind: func
    role: Converts any supported crypto.PublicKey into a JWK by dispatching on concrete type.
    why: Single entry point so callers needn't switch on key type themselves; unsupported types error instead of producing a malformed JWK.
  - name: RSAPublicKeyToJWK
    kind: func
    role: Builds the RSA-flavored JWK (n, e).
    why: Uses RawURLEncoding (no padding) per JWK spec so the output interoperates with standard JWKS consumers.
  - name: ECDSAPublicKeyToJWK
    kind: func
    role: Builds the EC-flavored JWK (crv, x, y).
    why: Derives x/y by slicing the uncompressed-point bytes from pub.Bytes() (Go 1.25+) instead of the deprecated X/Y big.Int fields, keeping fixed-width left-padded coordinates.
  - name: JWKToPublicKey
    kind: func
    role: Reconstructs a crypto.PublicKey (and its alg) from a JWK.
    why: Inverse of PublicKeyToJWK for verifying tokens against fetched JWKS; bounds-checks coordinate/exponent sizes to reject malformed or oversized remote keys.
  - name: ComputeKid
    kind: func
    role: Derives a deterministic kid for a key: RFC 7638 thumbprint for asymmetric keys, SHA-256 of raw bytes for HMAC.
    why: Deterministic kids let the same key produce the same identifier across processes/restarts; for []byte+asymmetric alg it auto-parses PEM so a PEM-stored RSA/EC key still gets a true thumbprint rather than a hash of its PEM text.
  - name: StrMap
    kind: type alias
    role: Alias for map[string]any used by Flask cookie decoding.
    why: An alias (not a defined type) so it interchanges freely with plain map[string]any at call sites.
  - name: FlaskAuth
    kind: struct
    role: Decodes and verifies Flask (itsdangerous/Fernet) session cookies for cross-stack auth interop.
    why: Exists to read sessions minted by a Python/Flask peer; LogCookies gates verbose secret-adjacent logging so it's off by default.
  - name: FlaskAuth.NormalizedSecretKey
    kind: method
    role: Pads/truncates the app secret to exactly 32 bytes and base64-encodes it for Fernet.
    why: Mirrors Flask's quirk of coercing arbitrary secrets to a 32-byte Fernet key — required for byte-compatible decryption, not a security choice.
  - name: FlaskAuth.DecodeSessionCookie
    kind: method
    role: Parses the signed/optionally-zlib-compressed base64 session payload into a StrMap.
    why: Reimplements itsdangerous' URL-safe base64 (-/_ → +//), '.'-prefix-means-compressed convention, and 4-char padding to match Flask's wire format exactly.
  - name: FlaskAuth.DecodeSessionUserId
    kind: method
    role: Fernet-decrypts and splits the encoded user-id field, decoding '~'-prefixed parts as base62-ish integers.
    why: The '~' marker and excelDecode base conversion replicate the host app's user-id encoding so numeric IDs round-trip correctly.
  - name: FlaskAuth.ParseSignedCookieValue
    kind: method
    role: End-to-end helper: decode cookie, pull _user_id, decrypt to id parts.
    why: Convenience facade returning both the parsed parts and the raw session map; logs and returns empty rather than erroring so a malformed cookie degrades to "unauthenticated".
depends_on: []
---

## Crypto and key helpers

`crypto_helpers.go` is the package's keystore-facing layer. The asymmetric path is deliberately narrow: RS256 and ES256 (P-256) only, with `SigningMethodForAlg` treating an unrecognized alg as a hard error and empty-string as HS256. `DecodeVerifyKey` is the seam that lets a `KeyStore` hand back either already-parsed key objects or raw PEM `[]byte` without callers caring.

## JWK / JWKS

`jwk.go` and `jwk_thumbprint.go` cover the JWK round-trip and kid derivation. The `JWK` struct is public-only by construction — the omission of private fields is a security invariant, not an oversight, so a `JWKSet` can never serialize private material. Coordinate handling uses the modern `(*ecdsa.PublicKey).Bytes()` (Go 1.25+) uncompressed-point form and fixed-width left-padding, and the reverse path bounds-checks sizes to reject hostile remote keys.

Kid derivation (`ComputeKid`) follows RFC 7638 for asymmetric keys — canonical lexicographically-ordered JSON (`{"e","kty","n"}` for RSA, `{"crv","kty","x","y"}` for EC) hashed with SHA-256 and RawURL-encoded to a stable 43-char string. HMAC keys instead hash their raw bytes. The notable subtlety: when given PEM `[]byte` for an asymmetric alg, it parses the PEM and computes a real thumbprint rather than hashing the PEM text, so the kid is stable regardless of storage encoding.

## Flask interop

`flask.go` is unrelated to OneAuth's own tokens — it exists purely to consume session cookies minted by a Flask peer (itsdangerous signing + Fernet-encrypted user ids). It reimplements Flask's wire conventions (URL-safe base64 substitution, `.`-prefix zlib compression flag, 32-byte secret coercion, `~`-marked base62 integer encoding) for byte-level compatibility. The helpers `paddedWith`, `alphaReverseMap`, and `excelDecode` were inlined from a former `goutils` dependency.
