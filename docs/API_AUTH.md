# API Authentication

OneAuth provides a complete API authentication system for mobile apps, SPAs, CLI tools, and service-to-service communication.

## Token Architecture

OneAuth uses a hybrid token architecture:

- **Access Tokens**: Short-lived JWTs (15 min default) containing user ID, scopes, and expiry. Validated statelessly without database lookup.
- **Refresh Tokens**: Long-lived opaque tokens (7 days default) stored in the database. Rotated on each use with theft detection.
- **API Keys**: Long-lived keys for automation. Stored as bcrypt hashes like passwords.

## Setting Up APIAuth

```go
import (
    "github.com/panyam/oneauth"
    "github.com/panyam/oneauth/stores/fs"
)

// Setup stores
storagePath := "/path/to/storage"
refreshTokenStore := fs.NewFSRefreshTokenStore(storagePath)
apiKeyStore := fs.NewFSAPIKeyStore(storagePath)

// Configure API authentication
apiAuth := &oneauth.APIAuth{
    ValidateCredentials: validateCreds, // From NewCredentialsValidator
    RefreshTokenStore:   refreshTokenStore,
    APIKeyStore:         apiKeyStore,
    JWTSecretKey:        os.Getenv("JWT_SECRET"),
    JWTIssuer:           "yourapp.com",
    JWTAudience:         "yourapp-api",
    AccessTokenExpiry:   15 * time.Minute,
    RefreshTokenExpiry:  7 * 24 * time.Hour,

    // Scope resolution callback
    GetUserScopes: func(userID string) ([]string, error) {
        return []string{"read", "write", "profile"}, nil
    },
}

// Mount routes
mux.Handle("/api/login", http.HandlerFunc(apiAuth.HandleLogin))
mux.Handle("/api/logout", http.HandlerFunc(apiAuth.HandleLogout))
mux.Handle("/api/logout-all", http.HandlerFunc(apiAuth.HandleLogoutAll))
mux.Handle("/api/keys", http.HandlerFunc(apiAuth.HandleAPIKeys))
```

## API Endpoints

### Password Grant

```http
POST /api/login
Content-Type: application/json

{"grant_type":"password","username":"user@example.com","password":"secret"}
```

Response:
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "a1b2c3d4e5f6...",
    "token_type": "Bearer",
    "expires_in": 900,
    "scope": "read write profile"
}
```

### Refresh Token Grant

```http
POST /api/login
Content-Type: application/json

{"grant_type":"refresh_token","refresh_token":"a1b2c3d4e5f6..."}
```

Returns a new token pair. The old refresh token is invalidated (rotation).

### Logout

```http
POST /api/logout
Content-Type: application/json

{"refresh_token":"a1b2c3d4e5f6..."}
```

Revokes the specified refresh token.

### Logout All Sessions

```http
POST /api/logout-all
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

Revokes all refresh tokens for the authenticated user.

## APIMiddleware

Protect API endpoints with the `APIMiddleware`:

```go
middleware := &oneauth.APIMiddleware{
    JWTSecretKey:    apiAuth.JWTSecretKey,
    JWTIssuer:       apiAuth.JWTIssuer,
    JWTAudience:     apiAuth.JWTAudience,
    APIKeyStore:     apiKeyStore,
    AuthHeader:      "Authorization", // Default
    TokenQueryParam: "token",         // Optional: accept token as query param
}
```

### Token Extraction

The middleware extracts tokens from two sources, in order of precedence:

1. **Authorization header** (default): `Authorization: Bearer <token>`
2. **Query parameter** (when `TokenQueryParam` is set): `GET /ws?token=<jwt>`

The query parameter fallback is useful for WebSocket clients and other contexts where setting HTTP headers is not possible. If both are present, the header takes precedence.

### Protecting Endpoints

```go
// Require valid token
mux.Handle("/api/protected", middleware.ValidateToken(handler))

// Require specific scopes
mux.Handle("/api/write", middleware.RequireScopes("write")(handler))

// Optional authentication (allows anonymous)
mux.Handle("/api/public", middleware.Optional(handler))
```

### Extracting User Info in Handlers

```go
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    userID := oneauth.GetUserIDFromAPIContext(r.Context())
    scopes := oneauth.GetScopesFromAPIContext(r.Context())
    authType := oneauth.GetAuthTypeFromAPIContext(r.Context()) // "jwt" or "api_key"

    // Extract custom (non-standard) claims injected via CustomClaimsFunc
    custom := oneauth.GetCustomClaimsFromContext(r.Context())
    if custom != nil {
        tenantID := custom["tenant_id"].(string)
    }
}
```

## API Key Management

### Create API Key

```http
POST /api/keys
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{"name":"CI/CD Key","scopes":["read","write"]}
```

Response:
```json
{
    "key": "oa_abc123...xyz789",
    "key_id": "oa_abc123",
    "name": "CI/CD Key",
    "scopes": ["read", "write"],
    "created_at": "2024-01-15T10:30:00Z"
}
```

**Important**: The full key is only shown once at creation time.

### List API Keys

```http
GET /api/keys
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Revoke API Key

```http
DELETE /api/keys/oa_abc123
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Using API Keys

API keys can be used instead of JWTs:

```bash
curl https://api.example.com/endpoint \
  -H "Authorization: Bearer oa_abc123...xyz789"
```

The middleware automatically detects API keys (by prefix) vs JWTs.

## Scopes

OneAuth provides built-in scopes:

```go
const (
    ScopeRead    = "read"     // Read user data
    ScopeWrite   = "write"    // Modify user data
    ScopeProfile = "profile"  // Access profile info
    ScopeOffline = "offline"  // Enable refresh tokens
)
```

Use `ValidateScopes` to check if requested scopes are allowed:

```go
granted := oneauth.ValidateScopes(requested, allowed)
```

## Token Rotation and Theft Detection

Refresh tokens are rotated on each use. If a token is reused (indicating potential theft), the entire token family is revoked:

```go
// First use: success, returns new token pair
newToken, err := refreshTokenStore.RotateRefreshToken(token, expiry)

// Second use of same token: ErrTokenReused
newToken, err := refreshTokenStore.RotateRefreshToken(token, expiry)
// err == oneauth.ErrTokenReused
// Entire family revoked automatically
```

## Custom Claims

Inject application-specific claims into JWTs using `CustomClaimsFunc`. This is useful for embedding metadata like tenant IDs, quotas, or client identifiers:

```go
apiAuth := &oneauth.APIAuth{
    JWTSecretKey: os.Getenv("JWT_SECRET"),
    JWTIssuer:    "yourapp.com",
    CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
        tenant := getTenantForUser(userID)
        return map[string]any{
            "tenant_id":  tenant.ID,
            "plan":       tenant.Plan,
            "max_seats":  tenant.MaxSeats,
        }, nil
    },
}
```

**Important**: Standard JWT claims (`sub`, `iss`, `aud`, `exp`, `iat`, `type`, `scopes`) cannot be overridden. Colliding keys are logged and silently ignored.

To extract custom claims on the validation side, use `ValidateAccessTokenFull`:

```go
userID, scopes, customClaims, err := apiAuth.ValidateAccessTokenFull(tokenString)
if err != nil {
    // handle error
}
tenantID := customClaims["tenant_id"].(string)
```

If `CustomClaimsFunc` is nil, behavior is identical to before (backwards-compatible). If the callback returns an error, `CreateAccessToken` fails and the error propagates.

## Multi-Tenant JWT Validation (KeyStore)

For architectures where multiple clients (hosts, tenants) each mint their own JWTs, use a `KeyStore` for per-client key lookup instead of a single shared secret.

### The Problem

With a single `JWTSecretKey`, all token issuers share one secret. This means:
- You can't revoke access for one issuer without rotating the key for all
- A compromised secret affects all clients
- You can't have different clients use different signing algorithms

### The Solution: KeyStore Interface

```go
type KeyStore interface {
    GetVerifyKey(clientID string) (any, error)    // verification key for this client
    GetSigningKey(clientID string) (any, error)    // signing key for this client
    GetExpectedAlg(clientID string) (string, error) // expected algorithm
}
```

For the full `KeyStore` and `WritableKeyStore` interface details and persistent implementations, see [STORES.md](STORES.md#keystore--writablekeystore).

### Setting Up Multi-Tenant Validation

```go
// 1. Create a KeyStore and register client keys
keyStore := oneauth.NewInMemoryKeyStore()
keyStore.RegisterKey("host-alpha", []byte("alpha-secret-key"), "HS256")
keyStore.RegisterKey("host-beta",  []byte("beta-secret-key"),  "HS256")

// 2. Configure middleware with KeyStore (replaces JWTSecretKey)
middleware := &oneauth.APIMiddleware{
    KeyStore:    keyStore,
    JWTIssuer:   "resource.example.com", // optional: still validates issuer
    APIKeyStore: apiKeyStore,            // optional: API keys still work
}

// 3. Protect endpoints — tokens are verified per-client
mux.Handle("/api/resource", middleware.ValidateToken(handler))
```

### How It Works

When a JWT arrives, the middleware:

1. Parses the token without verifying the signature
2. Extracts the `client_id` claim from the unverified payload
3. Calls `KeyStore.GetExpectedAlg(clientID)` — if the JWT's `alg` header doesn't match, the token is rejected (prevents algorithm confusion attacks)
4. Calls `KeyStore.GetVerifyKey(clientID)` — returns the key material for this client
5. Verifies the JWT signature with the client-specific key

If `KeyStore` is nil, the middleware falls back to single `JWTSecretKey` behavior (backwards-compatible).

### Minting Tokens for Multi-Tenant Systems

On the host/client side, use `CustomClaimsFunc` to embed the `client_id`:

```go
hostAuth := &oneauth.APIAuth{
    JWTSecretKey: hostSharedSecret,
    JWTIssuer:    "resource.example.com",
    CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
        return map[string]any{
            "client_id":     "host-alpha",
            "client_domain": "alpha.example.com",
            "max_rooms":     10,
            "max_msg_rate":  30.0,
        }, nil
    },
}

// Mint a scoped token for a user
token, _, err := hostAuth.CreateAccessToken("user-123", []string{"read", "write"})
```

### Algorithm Confusion Prevention

The `KeyStore.GetExpectedAlg()` method prevents algorithm confusion attacks. For example, if a client is registered with `HS256` but sends a token with `alg: none` or `alg: RS256`, the token is rejected before signature verification.

### Future: Asymmetric Keys

The `KeyStore` interface supports asymmetric signing:
- `GetVerifyKey` can return `*rsa.PublicKey` or `*ecdsa.PublicKey` for RS256/ES256
- `GetSigningKey` can return `*rsa.PrivateKey` or `*ecdsa.PrivateKey`
- Per-client algorithm choice: some clients use HS256, others use RS256
- Both modes coexist on the same middleware

## Host Registration

For federated systems where external hosts register and receive credentials for minting scoped JWTs, OneAuth provides:

- **`HostRegistrar`**: An embeddable HTTP handler for host CRUD operations (register, list, get, delete, rotate secret). Stores host credentials in a `WritableKeyStore`.
- **`MintRelayToken`**: A helper function that hosts call after authenticating their own users, producing scoped JWTs that downstream services can validate via KeyStore.

For the full registration flow and architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Security Considerations

1. **JWT Secret**: Use a strong, random secret (32+ bytes). Store in environment variables.
2. **HTTPS**: Always use HTTPS in production to protect tokens in transit.
3. **Token Expiry**: Keep access tokens short-lived (15 min). Use refresh tokens for longer sessions.
4. **API Key Storage**: Store API keys securely. They cannot be recovered if lost.
5. **Scope Validation**: Always validate scopes in your handlers for defense-in-depth.
