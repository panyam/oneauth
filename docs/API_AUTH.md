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
    "github.com/panyam/oneauth/apiauth"
    "github.com/panyam/oneauth/core"
    "github.com/panyam/oneauth/stores/fs"
)

// Setup stores
storagePath := "/path/to/storage"
refreshTokenStore := fs.NewFSRefreshTokenStore(storagePath)
apiKeyStore := fs.NewFSAPIKeyStore(storagePath)

// Configure API authentication
apiAuth := &apiauth.APIAuth{
    ValidateCredentials: validateCreds, // From NewCredentialsValidator
    RefreshTokenStore:   refreshTokenStore,
    APIKeyStore:         apiKeyStore,
    JWTSecretKey:        os.Getenv("JWT_SECRET"),  // HMAC signing (HS256)
    // JWTSigningKey:    privKey,   // Optional: *rsa.PrivateKey or *ecdsa.PrivateKey (RS256/ES256)
    // JWTVerifyKey:     pubKey,    // Optional: *rsa.PublicKey or *ecdsa.PublicKey
    // JWTSigningAlg:    "RS256",   // Set when using asymmetric keys
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

### Client Credentials Grant (RFC 6749 §4.4)

Machine-to-machine authentication. The client authenticates with `client_id` + `client_secret` and receives an access token with `sub=client_id`. No user context, no refresh token.

**Requires** `ClientKeyStore` to be configured on `APIAuth`:

```go
apiAuth := &apiauth.APIAuth{
    JWTSecretKey:   os.Getenv("JWT_SECRET"),
    ClientKeyStore: keyStore,  // KeyLookup for client credential lookup
    // ... other config
}
```

**Via client_secret_post** (credentials in request body, form-encoded per RFC 6749 §4.4.2):

```http
POST /api/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=billing-svc&client_secret=xxx&scope=billing:read
```

> Note: The token endpoint also accepts JSON bodies for backward compatibility, but
> form-encoded is the RFC 6749 standard and should be preferred for new integrations.
> The client SDK's `ClientCredentialsToken` now sends form-encoded requests.

**Via client_secret_basic** (HTTP Basic auth, RFC 6749 §2.3.1 default):

```http
POST /api/token
Authorization: Basic YmlsbGluZy1zdmM6eHh4
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=billing:read
```

Response:
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 900,
    "scope": "billing:read"
}
```

Note: no `refresh_token` — machine clients re-authenticate when the token expires.

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
middleware := &apiauth.APIMiddleware{
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
    userID := apiauth.GetUserIDFromAPIContext(r.Context())
    scopes := apiauth.GetScopesFromAPIContext(r.Context())
    authType := apiauth.GetAuthTypeFromAPIContext(r.Context()) // "jwt" or "api_key"

    // Extract custom (non-standard) claims injected via CustomClaimsFunc
    custom := apiauth.GetCustomClaimsFromContext(r.Context())
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

OneAuth provides built-in scopes (in `core`):

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
granted := core.ValidateScopes(requested, allowed)
```

## Token Rotation and Theft Detection

Refresh tokens are rotated on each use. If a token is reused (indicating potential theft), the entire token family is revoked:

```go
// First use: success, returns new token pair
newToken, err := refreshTokenStore.RotateRefreshToken(token, expiry)

// Second use of same token: ErrTokenReused
newToken, err := refreshTokenStore.RotateRefreshToken(token, expiry)
// err == core.ErrTokenReused
// Entire family revoked automatically
```

## Custom Claims

Inject application-specific claims into JWTs using `CustomClaimsFunc`. This is useful for embedding metadata like tenant IDs, quotas, or client identifiers:

```go
apiAuth := &apiauth.APIAuth{
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

For architectures where multiple clients (apps, tenants) each mint their own JWTs, use a `KeyStore` for per-client key lookup instead of a single shared secret.

### The Problem

With a single `JWTSecretKey`, all token issuers share one secret. This means:
- You can't revoke access for one issuer without rotating the key for all
- A compromised secret affects all clients
- You can't have different clients use different signing algorithms

### The Solution: KeyLookup / KeyStorage Interfaces

```go
type KeyLookup interface {
    GetKey(clientID string) (*KeyRecord, error)      // lookup by client ID
    GetKeyByKid(kid string) (*KeyRecord, error)      // lookup by key ID (RFC 7638 thumbprint)
}

type KeyStorage interface {
    KeyLookup
    PutKey(rec *KeyRecord) error
    DeleteKey(clientID string) error
    ListKeyIDs() ([]string, error)
}
```

For the full `KeyLookup` and `KeyStorage` interface details and persistent implementations, see [STORES.md](STORES.md#keylookup--keystorage).

### Setting Up Multi-Tenant Validation

```go
// 1. Create a KeyStore and register client keys
keyStore := keys.NewInMemoryKeyStore()
keyStore.PutKey(&keys.KeyRecord{ClientID: "app-alpha", Key: []byte("alpha-secret-key"), Algorithm: "HS256"})
keyStore.PutKey(&keys.KeyRecord{ClientID: "app-beta",  Key: []byte("beta-secret-key"),  Algorithm: "HS256"})

// 2. Configure middleware with KeyStore (replaces JWTSecretKey)
middleware := &apiauth.APIMiddleware{
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
3. Calls `KeyStore.GetKey(clientID)` — returns a `*KeyRecord` containing the key and expected algorithm; if the JWT's `alg` header doesn't match `rec.Algorithm`, the token is rejected (prevents algorithm confusion attacks)
4. Uses `rec.Key` — the key material for this client
5. Verifies the JWT signature with the client-specific key

If `KeyStore` is nil, the middleware falls back to single `JWTSecretKey` behavior (backwards-compatible).

### Minting Tokens for Multi-Tenant Systems

On the app/client side, use `CustomClaimsFunc` to embed the `client_id`:

```go
hostAuth := &apiauth.APIAuth{
    JWTSecretKey: hostSharedSecret,
    JWTIssuer:    "resource.example.com",
    CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
        return map[string]any{
            "client_id":     "app-alpha",
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

The `KeyRecord.Algorithm` field prevents algorithm confusion attacks. When a token arrives, the middleware calls `GetKey(clientID)` and compares the JWT's `alg` header against `rec.Algorithm`. If a client is registered with `HS256` but sends a token with `alg: none` or `alg: RS256`, the token is rejected before signature verification.

### Future: Asymmetric Keys

The `KeyStore` interface supports asymmetric signing:
- `GetKey` returns a `*KeyRecord` whose `Key` field can be `*rsa.PublicKey` or `*ecdsa.PublicKey` for RS256/ES256
- For signing, `Key` can be `*rsa.PrivateKey` or `*ecdsa.PrivateKey`
- Per-app algorithm choice: some apps use HS256, others use RS256
- Both modes coexist on the same middleware

## App Registration

For federated systems where external apps register and receive credentials for minting scoped JWTs, OneAuth provides:

- **`AppRegistrar`**: An embeddable HTTP handler for app CRUD operations (register, list, get, delete, rotate secret). Stores app credentials in a `KeyStorage`.
- **`MintResourceToken`**: A helper function that apps call after authenticating their own users, producing scoped JWTs that downstream resource servers can validate via KeyStore.

For the full registration flow and architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Recent Changes

### RateLimiter interface moved to core

The `RateLimiter` interface previously in `apiauth` has moved to `core` so it can be shared with `localauth`. The interface is unchanged — update imports from `apiauth.RateLimiter` to `core.RateLimiter`. `core.InMemoryRateLimiter` is available for both API and browser auth.

### Token Blacklist (jti-based revocation)

Access tokens now include a `jti` (JWT ID) claim (RFC 7519 §4.1.7). When `APIAuth.Blacklist` or `APIMiddleware.Blacklist` is set, revoked token IDs are checked during validation.

```go
bl := core.NewInMemoryBlacklist()
auth := &apiauth.APIAuth{
    JWTSecretKey: secret,
    Blacklist:    bl,  // enables immediate token revocation
}
middleware := &apiauth.APIMiddleware{
    JWTSecretKey: secret,
    Blacklist:    bl,  // same blacklist shared with middleware
}

// Revoke a token by its jti claim
bl.Revoke(jti, tokenExpiry)
```

Backward compatible: when `Blacklist` is nil (default), tokens are validated by signature + expiry only.

For distributed deployments, implement `core.TokenBlacklist` backed by Redis (`SET jti:<id> 1 EX <ttl>`).

### Audience validation in ValidateAccessToken

`ValidateAccessToken` now checks the `aud` (audience) claim when `JWTAudience` is configured on `APIAuth` or `APIMiddleware`. Previously the audience was set when minting but not validated on verification. Tokens minted without an `aud` claim are still accepted when `JWTAudience` is empty.

**Array audience support (#52):** Per RFC 7519 §4.1.3, the `aud` claim may be a single string or an array of strings. All validation sites (`ValidateAccessToken`, `ValidateAccessTokenFull`, `APIMiddleware.validateJWT`) handle both formats. This ensures interoperability with Keycloak, Auth0, Azure AD, and other IdPs that send `aud` as an array (e.g., `["api://default", "https://example.com"]`).

### SigningMethodForAlg returns error

`SigningMethodForAlg` now returns `(jwt.SigningMethod, error)` instead of just `jwt.SigningMethod`. Unknown or unsupported algorithm strings return an error rather than silently falling back. Callers must handle the error.

### TokenPair moved to core

`TokenPair` has moved from `apiauth` to `core`. Update imports: `apiauth.TokenPair` becomes `core.TokenPair`.

## Protected Resource Metadata (RFC 9728)

Resource servers can advertise their capabilities at `GET /.well-known/oauth-protected-resource` so OAuth clients can auto-discover which auth servers to use, what scopes to request, and what token formats are supported.

```go
import "github.com/panyam/oneauth/apiauth"

meta := &apiauth.ProtectedResourceMetadata{
    Resource:              "https://api.example.com",
    AuthorizationServers:  []string{"https://auth.example.com"},
    ScopesSupported:       []string{"read", "write"},
    TokenFormatsSupported: []string{"jwt"},
    SigningAlgsSupported:  []string{"RS256", "ES256"},
}
mux.Handle("GET /.well-known/oauth-protected-resource",
    apiauth.NewProtectedResourceHandler(meta))
```

Response:
```json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["read", "write"],
  "token_formats_supported": ["jwt"],
  "resource_signing_alg_values_supported": ["RS256", "ES256"]
}
```

The handler sets `Cache-Control: public, max-age=3600` by default (configurable via `CacheMaxAge`). Only responds to GET (405 for other methods). Optional fields are omitted when empty.

See [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) for the full specification.

## Token Introspection (RFC 7662)

Resource servers can validate tokens by querying the auth server instead of doing local JWT validation via JWKS. This enables blacklist checking, supports opaque tokens, and simplifies resource server implementations.

```go
import "github.com/panyam/oneauth/apiauth"

handler := &apiauth.IntrospectionHandler{
    Auth:           apiAuth,       // APIAuth with JWTSecretKey configured
    ClientKeyStore: keyStore,      // Authenticates calling resource servers
}
mux.Handle("POST /oauth/introspect", handler)
```

Resource servers call the endpoint with HTTP Basic auth (using their client_credentials):

```http
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=eyJhbGciOiJIUzI1NiIs...
```

Active token response:
```json
{
    "active": true,
    "sub": "user-42",
    "scope": "read write",
    "iss": "yourapp.com",
    "exp": 1699999999,
    "iat": 1699999000,
    "jti": "unique-token-id",
    "token_type": "access_token"
}
```

Inactive token response (expired, revoked, invalid, tampered — never reveals why):
```json
{
    "active": false
}
```

Responses include `Cache-Control: no-store` and `Pragma: no-cache` per RFC 7662.

See [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) for the full specification.

## OIDC Discovery / AS Metadata (RFC 8414)

The auth server can advertise its endpoints at `GET /.well-known/openid-configuration` so OIDC-aware clients auto-discover them. This is metadata-only — it does NOT make OneAuth a full OIDC provider.

```go
import "github.com/panyam/oneauth/apiauth"

handler := apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
    Issuer:                "https://auth.example.com",
    TokenEndpoint:         "https://auth.example.com/api/token",
    JWKSURI:               "https://auth.example.com/.well-known/jwks.json",
    IntrospectionEndpoint: "https://auth.example.com/oauth/introspect",
    GrantTypesSupported:   []string{"password", "refresh_token", "client_credentials"},
    ResponseTypesSupported: []string{"token"},
    TokenEndpointAuthMethods: []string{"client_secret_post", "client_secret_basic"},
})
mux.Handle("GET /.well-known/openid-configuration", handler)
```

Clients discover endpoints via `client.DiscoverAS()` (#51):

```go
meta, _ := client.DiscoverAS("https://auth.example.com")
// meta.TokenEndpoint, meta.JWKSURI, meta.IntrospectionEndpoint, etc.
```

See [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) for the full specification.

## Security Considerations

1. **JWT Secret**: Use a strong, random secret (32+ bytes). Store in environment variables.
2. **HTTPS**: Always use HTTPS in production to protect tokens in transit.
3. **Token Expiry**: Keep access tokens short-lived (15 min). Use refresh tokens for longer sessions.
4. **API Key Storage**: Store API keys securely. They cannot be recovered if lost.
5. **Scope Validation**: Always validate scopes in your handlers for defense-in-depth.
6. **Audience Validation**: Set `JWTAudience` to prevent tokens minted for other services from being accepted. Both string and array `aud` claims are supported (RFC 7519 §4.1.3).
