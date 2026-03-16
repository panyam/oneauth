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

## See Also

- [FEDERATED_AUTH.md](FEDERATED_AUTH.md) — end-to-end federated auth flow with registration, minting, and validation
- [API_AUTH.md](API_AUTH.md) — APIAuth and APIMiddleware configuration
- [STORES.md](STORES.md) — KeyStore and WritableKeyStore interface details
