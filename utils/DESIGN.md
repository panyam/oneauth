# utils

Stateless package of crypto and encoding helpers shared across OneAuth: RSA/ECDSA key generation, PEM/PKCS8 encode-and-parse round-trips, JWK/JWKS conversion in both directions, RFC 7638 JWK Thumbprint computation for deterministic `kid`s, a single typed lookup from algorithm string to `jwt.SigningMethod`, and a self-contained Flask session-cookie decoder for interop with Python backends. Every export is a pure function, type alias, or value-holding struct — no init, no globals, no I/O beyond Flask debug logging.

## Contents

- [Entities](#entities)
- [Flows](#flows)
  - [JWK round-trip preserves the kid](#jwk-round-trip-preserves-the-kid)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `MinRSAKeySize` | const | Minimum RSA key size in bits (2048). | Enforces the NIST SP 800-57 floor at generation time. |
| `GenerateRSAKeyPair` | func | Generates an RSA pair as PEM-encoded private/public bytes. | Single entry point that pairs key generation with the `MinRSAKeySize` floor. |
| `GenerateECDSAKeyPair` | func | Generates an ECDSA P-256 pair as PEM-encoded private/public bytes. | P-256 is hard-coded since it is the only curve the JWK path supports. |
| `ParsePublicKeyPEM` | func | Parses a PKIX public-key PEM into a `crypto.PublicKey`. | One parser handles RSA and ECDSA via PKIX SubjectPublicKeyInfo. |
| `ParsePrivateKeyPEM` | func | Parses a PKCS8 private-key PEM into a `crypto.PrivateKey`. | PKCS8-only so callers cannot accidentally feed PKCS1/SEC1 blocks. |
| `EncodePublicKeyPEM` | func | Encodes a `crypto.PublicKey` as PKIX `PUBLIC KEY` PEM. | Mirror of `ParsePublicKeyPEM` so round-trips are symmetric. |
| `EncodePrivateKeyPEM` | func | Encodes a `crypto.PrivateKey` as PKCS8 `PRIVATE KEY` PEM. | Always PKCS8 so one parser handles both RSA and ECDSA. |
| `DecodeVerifyKey` | func | Normalizes raw key material into the JWT verify-key type for an alg. | HMAC passes through, RS256/ES256 PEM-parse, already-typed keys are returned as-is — idempotent so callers can pre-parse. |
| `IsAsymmetricAlg` | func | Reports whether an alg is RS256 or ES256. | The single gate between PEM-parse and raw-bytes branches throughout the package. |
| `SigningMethodForAlg` | func | Maps an alg string to a `jwt.SigningMethod`. | Errors on unknown algs instead of silently defaulting to HS256; empty string is the one allowed HS256 alias. |
| `JWK` | struct | RFC 7517 JSON Web Key holding only public components. | Private fields (`d`, `p`, `q`, `dp`, `dq`, `qi`) are intentionally omitted so they cannot leak via JWKS. |
| `JWKSet` | struct | RFC 7517 §5 wrapper for a list of JWKs. | Standard JWKS endpoint payload shape. |
| `PublicKeyToJWK` | func | Converts any `crypto.PublicKey` to a JWK by dispatching on key type. | Unsupported types error rather than producing a partial JWK, so publishers get a single safe call. |
| `RSAPublicKeyToJWK` | func | Builds an RSA JWK with `use=sig` and `key_ops=[verify]`. | Restricts the advertised key to verification to discourage misuse. |
| `ECDSAPublicKeyToJWK` | func | Builds an EC JWK with zero-padded x/y coordinates. | Uses `pub.Bytes()` (Go 1.25+) over deprecated X/Y and pads to the curve coordinate length so JWKs are byte-stable. |
| `JWKToPublicKey` | func | Reconstructs a `crypto.PublicKey` and alg from a JWK. | Validates exponent and coordinate sizes so malformed JWKs error instead of building invalid keys. |
| `ComputeKid` | func | Computes a deterministic 43-char kid for a key. | RFC 7638 thumbprint for asymmetric keys, SHA-256 base64url for HMAC; `[]byte` under an asymmetric alg is parsed to take the thumbprint path. |
| `StrMap` | type | Alias for `map[string]any` used for decoded Flask payloads. | Shorthand so cookie code does not repeat the long type. |
| `FlaskAuth` | struct | Decodes and verifies Flask session cookies from an app secret. | Self-contained interop with a Python Flask backend; `LogCookies` gates verbose debug logging. |
| `FlaskAuth.NormalizedSecretKey` | method | Pads or truncates the secret to 32 bytes and base64-encodes it as a Fernet key. | Mirrors Flask's derivation quirk so Fernet decryption matches the Python side. |
| `FlaskAuth.DecodeSessionCookie` | method | Decodes a base64 cookie body into a `StrMap`. | Handles the optional `.` prefix that signals zlib-compressed payloads and normalizes URL-safe base64. |
| `FlaskAuth.DecodeSessionUserId` | method | Fernet-decrypts a session user ID into its `|`-split parts. | `~`-prefixed parts are excel-base-decoded back to numeric IDs, matching the Flask convention. |
| `FlaskAuth.ParseSignedCookieValue` | method | Extracts `_user_id` parts plus the full session map from a signed cookie. | Composes `DecodeSessionCookie` and `DecodeSessionUserId` so callers get both halves in one call. |

## Flows

### JWK round-trip preserves the kid

The package is the canonical source of `kid`s for the entire project, and three independent code paths must agree byte-for-byte: minting a kid from a freshly generated key, computing one from a publish-side `JWK`, and computing one again on the verify side after parsing the JWK back into a `*ecdsa.PublicKey` or `*rsa.PublicKey`. The agreement depends entirely on zero-padding EC coordinates to the curve length on both sides, and on the lexicographic field order RFC 7638 mandates inside the canonical JSON string. The sequence below is the EC path; RSA is structurally identical but with `{e, kty, n}` instead of `{crv, kty, x, y}`.

```mermaid
sequenceDiagram
    participant Gen as GenerateECDSAKeyPair
    participant Kid as ComputeKid
    participant Pub as ECDSAPublicKeyToJWK
    participant Set as JWKSet (wire)
    participant Back as ecJWKToPublicKey
    participant Kid2 as ComputeKid (verify)

    Gen->>Kid: *ecdsa.PrivateKey
    Kid->>Kid: pub.Bytes() -> 0x04||X||Y; slice at byteLen
    Kid->>Kid: SHA-256({"crv","kty","x","y"} canonical JSON)
    Kid-->>Gen: kid (43 chars base64url)

    Gen->>Pub: pub, alg=ES256, kid
    Pub->>Pub: same byteLen slice, base64url no-pad
    Pub-->>Set: JWK{Kty:EC, Crv:P-256, X, Y, Kid, Alg, Use, KeyOps}

    Set->>Back: JWK
    Back->>Back: base64url decode X, Y
    Back->>Back: left-pad to byteLen, build 0x04||X||Y
    Back->>Back: ecdsa.ParseUncompressedPublicKey
    Back-->>Kid2: *ecdsa.PublicKey
    Kid2->>Kid2: same canonical-JSON hash
    Kid2-->>Set: kid == original (byte-equal)
```

## Gotchas

- **RFC 7638 canonicalization is fragile** — `rsaThumbprint` and `ecdsaThumbprint` build the canonical JSON by string formatting (`{"e":"%s","kty":"RSA","n":"%s"}` for RSA; `{"crv":"%s","kty":"EC","x":"%s","y":"%s"}` for EC) with members in lexicographic order and no whitespace. Any reordering, extra whitespace, padding on the base64url, or use of the encoding-with-padding variant changes the SHA-256 and therefore the `kid`. Do not rewrite this with `encoding/json` — Go's marshaller doesn't guarantee field order across struct changes.

- **EC coordinates must be zero-padded to the curve length** — both `ECDSAPublicKeyToJWK` and `ecdsaThumbprint` slice `pub.Bytes()` (the uncompressed `0x04 || X || Y` encoding from Go 1.25+) at `1+byteLen` rather than emitting `X.Bytes()` / `Y.Bytes()` directly. The reverse path in `ecJWKToPublicKey` then left-pads short input back to `byteLen` before reassembling the uncompressed point. Skipping this padding produces a different thumbprint for the same key whenever a coordinate happens to start with leading zero bytes.

- **`ComputeKid([]byte, asymmetric-alg)` parses the PEM first** — passing raw PEM bytes with `alg = "RS256"` or `"ES256"` triggers `DecodeVerifyKey`, so the kid becomes the RFC 7638 thumbprint of the public key, not the SHA-256 of the PEM bytes. Two different PEM serializations of the same key therefore produce the same kid (the desired behavior), but pre-parsed `*rsa.PublicKey` and raw PEM `[]byte` inputs only agree because of this fallback — if PEM parsing fails the code silently falls through to hashing the raw bytes. Inspect errors if you need that distinction.

- **HS256 secrets are deliberately excluded from JWKs** — `JWK` and `PublicKeyToJWK` only know `*rsa.PublicKey` and `*ecdsa.PublicKey`; HMAC secrets cannot be turned into a JWK by this package, which is intentional (they would leak the signing secret). The companion `kid` path still works for HMAC: `ComputeKid([]byte, "HS256")` returns `SHA-256(secret)` base64url-encoded — that's the kid HMAC tokens reference even though no JWK is ever published.

- **`SigningMethodForAlg("")` returns HS256, not an error** — empty string is the one allowed alias, kept for single-tenant deployments that never set the field. Any other unknown value errors; do not assume omitting the alg fails closed. `"none"` is not in the switch — it falls into the default error branch, which is the correct behavior (the JWT `alg=none` attack class is shut at the lookup, before any signing method is ever instantiated).

- **PKCS8-only by design** — `ParsePrivateKeyPEM` and `EncodePrivateKeyPEM` only handle PKCS8. Passing a PKCS1 (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) block fails at the `x509.ParsePKCS8PrivateKey` step. `GenerateRSAKeyPair` / `GenerateECDSAKeyPair` always emit PKCS8, so this only bites external callers feeding in keys generated by `openssl`/`ssh-keygen`.

- **`GenerateECDSAKeyPair` is hard-coded to P-256** — there is no parameter for curve selection. P-384/P-521 keys would need a new entry point because `ecJWKToPublicKey` only accepts `P-256` and `SigningMethodForAlg` only maps `ES256`. Don't add a curve here without extending both reverse paths.

- **`MinRSAKeySize = 2048` rejects 1024 at generation time only** — the floor lives in `GenerateRSAKeyPair`. Externally-supplied PEMs parsed via `ParsePrivateKeyPEM` are not size-checked, so a weak key loaded from disk passes through silently. Callers that load keys from configuration must validate `pub.N.BitLen()` themselves.

- **`FlaskAuth.NormalizedSecretKey` mutates the struct** — the loop pads `f.AppSecretKey` in place until it is at least 32 bytes, then truncates to 32. Successive calls with a short secret keep appending until the field is permanently 32 spaces of padding. Treat `FlaskAuth` as call-once or set `AppSecretKey` to exactly 32 bytes up front.

- **`FlaskAuth.DecodeSessionUserId` will panic on empty parts** — it indexes `part[0]` without checking `len(part) > 0`, so a `|` at the end of the decrypted payload, or two consecutive `|`s, crash the goroutine. This code path runs on attacker-supplied cookie values; treat it as a hardening gap, not a contract.

- **Flask cookie decoder uses URL-safe → standard base64 swap, not `base64.URLEncoding`** — `DecodeSessionCookie` walks the string replacing `-`→`+` and `_`→`/` then calls `base64.StdEncoding.DecodeString` on each `.`-separated part after padding with `=`. Don't "simplify" this to `base64.RawURLEncoding`: the parts can be of different lengths and the `paddedWith` helper assumes the standard-alphabet variant.

- **Constant-time comparisons are not used** — none of the helpers here do HMAC/signature verification themselves (Fernet does, internally), so there are no `crypto/subtle` calls in this package. JWT signature verification happens in callers via `jwt.SigningMethod`. Don't add equality checks on secrets or signatures to this file without `subtle.ConstantTimeCompare`.

## Depends on

*(no internal dependencies)*
