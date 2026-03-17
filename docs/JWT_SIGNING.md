# JWT Signing & Key Verification

OneAuth supports three JWT signing algorithms. Each can be used per-app in the same deployment — HS256, RS256, and ES256 apps coexist in a shared KeyStore.

## Algorithm Overview

| Algorithm | Type | Key Type | When to Use |
|-----------|------|----------|-------------|
| **HS256** | Symmetric (HMAC-SHA256) | Shared `[]byte` secret | Simple setups where all parties are trusted. App and resource server share the same secret. |
| **RS256** | Asymmetric (RSA-SHA256) | `*rsa.PrivateKey` / `*rsa.PublicKey` | Federated auth where apps keep private keys secret. Resource servers only get the public key. Wider ecosystem compatibility. |
| **ES256** | Asymmetric (ECDSA-P256-SHA256) | `*ecdsa.PrivateKey` / `*ecdsa.PublicKey` | Same as RS256 but with smaller keys and faster signatures. Preferred for new deployments. |

### When to Use Asymmetric (RS256/ES256)

- Resource servers should not be able to forge tokens
- Multiple resource servers validate tokens from the same app
- You want to rotate keys without coordinating secret distribution
- Compliance requires separation of signing and verification

### When HS256 Is Fine

- Single app + single resource server, both fully trusted
- Internal services behind a VPN
- Simplest possible setup (no key pair management)

## Key Generation

### Using Go (`utils/crypto_helpers.go`)

```go
import "github.com/panyam/oneauth/utils"

// RSA (2048-bit minimum, 4096 for high security)
privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)

// ECDSA P-256 (smaller keys, faster)
privPEM, pubPEM, err := utils.GenerateECDSAKeyPair()
```

### Using OpenSSL

```bash
# RSA
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out app-private.pem
openssl pkey -in app-private.pem -pubout -out app-public.pem

# ECDSA P-256
openssl ecparam -genkey -name prime256v1 -noout -out app-private.pem
openssl pkey -in app-private.pem -pubout -out app-public.pem
```

## PEM Encode/Decode

All key material is stored and transmitted as PEM-encoded bytes. The `utils` package provides round-trip helpers:

```go
// Parse PEM → crypto key
privKey, err := utils.ParsePrivateKeyPEM(privPEM)  // → *rsa.PrivateKey or *ecdsa.PrivateKey
pubKey, err := utils.ParsePublicKeyPEM(pubPEM)      // → *rsa.PublicKey or *ecdsa.PublicKey

// Encode crypto key → PEM
privPEM = utils.EncodePrivateKeyPEM(privKey)         // PKCS8 format
pubPEM, err = utils.EncodePublicKeyPEM(pubKey)       // PKIX format
```

## Minting Tokens

### HS256 (symmetric — existing API)

```go
token, err := oneauth.MintResourceToken(
    "user-42", "app_abc123",
    "shared-secret",              // string → []byte internally
    oneauth.AppQuota{MaxRooms: 10},
    []string{"relay:connect"},
)
```

### RS256/ES256 (asymmetric — new API)

```go
privKey, _ := utils.ParsePrivateKeyPEM(privPEM)

token, err := oneauth.MintResourceTokenWithKey(
    "user-42", "app_abc123",
    privKey,                       // *rsa.PrivateKey → RS256, *ecdsa.PrivateKey → ES256
    oneauth.AppQuota{MaxRooms: 10},
    []string{"relay:connect"},
)
```

Algorithm is auto-detected from the key type. No separate `alg` parameter needed.

## APIAuth Configuration

### Symmetric (HS256)

```go
auth := &oneauth.APIAuth{
    JWTSecretKey: "my-secret",  // shared secret
    JWTIssuer:    "myapp",
}
```

### Asymmetric (RS256/ES256)

```go
auth := &oneauth.APIAuth{
    JWTSigningAlg: "RS256",
    JWTSigningKey: privKey,    // *rsa.PrivateKey for signing
    JWTVerifyKey:  pubKey,     // *rsa.PublicKey for verification
    JWTIssuer:     "myapp",
}
```

When `JWTSigningKey`/`JWTVerifyKey` are set, they take precedence over `JWTSecretKey`. The `jwtKeyFunc` validates that the token's algorithm matches the key type, preventing algorithm confusion.

## App Registration

### Symmetric (HS256) — default

```bash
curl -X POST https://auth.example.com/apps/register \
  -H "X-Admin-Key: admin-key" \
  -d '{"client_domain": "myapp.com", "signing_alg": "HS256"}'
```

Response includes `client_secret` (shown only once).

### Asymmetric (RS256/ES256)

```bash
curl -X POST https://auth.example.com/apps/register \
  -H "X-Admin-Key: admin-key" \
  -d '{
    "client_domain": "myapp.com",
    "signing_alg": "RS256",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----"
  }'
```

Response omits `client_secret` — the app keeps its private key.

### Key Rotation

**Symmetric**: `POST /apps/{client_id}/rotate` — generates a new secret, returns it.

**Asymmetric**: `POST /apps/{client_id}/rotate` with `{"public_key": "..."}` — replaces the stored public key.

## KeyStore & DecodeVerifyKey

All KeyStore backends (InMemory, FS, GORM, GAE) store key material as `[]byte`:
- HS256: raw shared secret bytes
- RS256/ES256: PEM-encoded public key bytes

No storage schema changes are needed for asymmetric keys.

At validation time, `utils.DecodeVerifyKey(rawKey, alg)` converts stored bytes to the appropriate type:

```go
// In APIMiddleware.validateJWT (automatic):
rawKey, _ := m.KeyStore.GetVerifyKey(clientID)
verifyKey, _ := utils.DecodeVerifyKey(rawKey, expectedAlg)
// HS256 → returns []byte as-is
// RS256 → parses PEM → *rsa.PublicKey
// ES256 → parses PEM → *ecdsa.PublicKey
```

## Algorithm Confusion Prevention

OneAuth prevents algorithm confusion attacks at multiple levels:

1. **KeyStore.GetExpectedAlg()**: Every client has a registered algorithm. The middleware rejects tokens whose `alg` header doesn't match.

2. **APIAuth.jwtKeyFunc()**: Validates that the token's signing method matches the configured key type (RSA method for RSA key, ECDSA method for ECDSA key, HMAC method for symmetric key).

3. **DecodeVerifyKey type checking**: RS256 keys must parse to `*rsa.PublicKey`, ES256 to `*ecdsa.PublicKey`. A PEM containing the wrong key type is rejected.

This means an attacker cannot:
- Send `alg: none` to skip verification
- Send `alg: HS256` with a public key as the HMAC secret
- Send `alg: RS256` for an app registered with HS256

## SigningMethodForAlg / IsAsymmetricAlg

```go
utils.SigningMethodForAlg("RS256")    // → jwt.SigningMethodRS256
utils.SigningMethodForAlg("ES256")    // → jwt.SigningMethodES256
utils.SigningMethodForAlg("HS256")    // → jwt.SigningMethodHS256 (default)

utils.IsAsymmetricAlg("RS256")       // → true
utils.IsAsymmetricAlg("ES256")       // → true
utils.IsAsymmetricAlg("HS256")       // → false
```

## JWKS (JSON Web Key Set)

OneAuth supports standard JWKS (RFC 7517) for public key discovery. The auth server exposes asymmetric keys at `/.well-known/jwks.json`, and resource servers can fetch them via `JWKSKeyStore`.

### JWK Conversion (`utils/jwk.go`)

```go
import "github.com/panyam/oneauth/utils"

// Convert public key → JWK
jwk, err := utils.PublicKeyToJWK("app_abc", "RS256", rsaPublicKey)

// Convert JWK → public key
pubKey, alg, err := utils.JWKToPublicKey(jwk)
```

Supported key types: RSA (`kty: "RSA"`) and ECDSA P-256 (`kty: "EC"`, `crv: "P-256"`).

### Serving JWKS (`JWKSHandler`)

```go
handler := &oa.JWKSHandler{
    KeyStore:    keyStore,  // WritableKeyStore (needs ListKeys)
    CacheMaxAge: 3600,      // Cache-Control max-age (default: 3600)
}
mux.HandleFunc("GET /.well-known/jwks.json", handler.ServeHTTP)
```

Only asymmetric keys (RS256/ES256) are included. HS256 secrets are never exposed.

### Fetching JWKS (`JWKSKeyStore`)

```go
ks := oa.NewJWKSKeyStore("https://auth.example.com/.well-known/jwks.json",
    oa.WithRefreshInterval(30 * time.Minute),
)
ks.Start()
defer ks.Stop()

// Use as a read-only KeyStore
key, _ := ks.GetVerifyKey("app_abc")    // → *rsa.PublicKey or *ecdsa.PublicKey
alg, _ := ks.GetExpectedAlg("app_abc")  // → "RS256" or "ES256"
```

See [FEDERATED_AUTH.md](FEDERATED_AUTH.md#jwks-public-key-discovery) for the full JWKS guide.

## Encryption at Rest (EncryptedKeyStore)

HS256 `client_secret` values are stored in the KeyStore as raw `[]byte`. To protect them at rest (e.g., against database dumps), wrap any `WritableKeyStore` with `EncryptedKeyStore`:

```go
import oa "github.com/panyam/oneauth"

inner := gormstore.NewKeyStore(db)
encrypted, err := oa.NewEncryptedKeyStore(inner, os.Getenv("ONEAUTH_MASTER_KEY"))
```

### Master Key

- 64-character hex string (32 bytes): `openssl rand -hex 32`
- Set via `ONEAUTH_MASTER_KEY` env var or `keystore.master_key` in YAML config
- Never stored alongside the data it protects
- The raw master key is not used directly — HKDF-SHA256 derives an encryption-specific key with info string `"oneauth-keystore-encryption-v1"`

### What Gets Encrypted

| Algorithm | Key Type | Encrypted? |
|-----------|----------|------------|
| HS256/HS384/HS512 | Shared `[]byte` secret | Yes (AES-256-GCM) |
| RS256 | `[]byte` PEM (public key) | No (not sensitive) |
| ES256 | `[]byte` PEM (public key) | No (not sensitive) |

### Migration

If you enable encryption on an existing deployment, existing plaintext secrets remain readable. The wrapper attempts GCM decryption on read; if it fails, it returns the raw bytes as plaintext. New writes are always encrypted.

### Reference Server Configuration

```yaml
keystore:
  type: "gorm"
  master_key: "${ONEAUTH_MASTER_KEY}"
  gorm:
    driver: "postgres"
    dsn: "${DATABASE_URL}"
```

Or via environment variable (e.g., GAE):
```bash
export ONEAUTH_MASTER_KEY="$(openssl rand -hex 32)"
```

### Shared KeyStore Requirement

When resource servers share the same KeyStore database as the auth server, they must also have the same `ONEAUTH_MASTER_KEY` to decrypt HS256 secrets. Resource servers using JWKS discovery are unaffected (JWKS only serves asymmetric keys).

## See Also

- [FEDERATED_AUTH.md](FEDERATED_AUTH.md) — end-to-end federated auth flow with registration, minting, and validation
- [API_AUTH.md](API_AUTH.md) — APIAuth and APIMiddleware configuration
- [STORES.md](STORES.md) — KeyStore and WritableKeyStore interface details
