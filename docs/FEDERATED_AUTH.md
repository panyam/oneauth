# Federated Authentication

OneAuth supports a federated authentication model where multiple Apps register with a central auth service, obtain credentials, and mint scoped JWTs that downstream resource servers (e.g., a WebSocket relay like massrelay) validate using a shared KeyStore.

## Architecture Overview

Three projects collaborate in a federated deployment:

1. **oneauth** (this repo) — shared auth library + App Registration API
2. **Resource server** (e.g., massrelay) — validates resource-scoped JWTs using KeyStore
3. **App** (e.g., excaliframe) — registers as an App, authenticates users locally, mints resource tokens

```
┌───────────────┐     1. register         ┌───────────────────┐
│     App       │ ──────────────────────→ │  OneAuth Server   │
│ (excaliframe) │ ←─────────────────────  │  (AppRegistrar)   │
│               │  client_id + secret     │                   │
└───────┬───────┘                         └────────┬──────────┘
        │                                          │
        │ 2. authenticate user locally             │ shared KeyStore
        │ 3. mint resource-scoped JWT              │ (GORM, FS, GAE)
        │                                          │
        ▼                                          ▼
┌───────────────┐  4. connect with JWT    ┌───────────────────┐
│   End User    │ ──────────────────────→ │ Resource Server   │
│   (browser)   │                         │ (APIMiddleware +  │
│               │                         │  KeyStore)        │
└───────────────┘                         └───────────────────┘
```

## End-to-End Flow

### Step 1: App Registers with OneAuth Server

The App sends a registration request to the OneAuth server, protected by admin authentication.

```bash
curl -X POST https://auth.example.com/apps/register \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "client_domain": "excaliframe.com",
    "signing_alg": "HS256",
    "max_rooms": 10,
    "max_msg_rate": 30.0
  }'
```

Response (201 Created):
```json
{
  "client_id": "app_a1b2c3d4e5f6",
  "client_secret": "64-char-hex-string...",
  "client_domain": "excaliframe.com",
  "signing_alg": "HS256",
  "max_rooms": 10,
  "max_msg_rate": 30.0,
  "created_at": "2026-03-15T10:30:00Z"
}
```

The `client_secret` is stored in the `WritableKeyStore` and shared with the resource server.

### Step 2: App Authenticates Users Locally

The App uses its own authentication system (could be oneauth's `LocalAuth`, OAuth, or anything else) to verify the user's identity.

### Step 3: App Mints a Resource Token

After authenticating a user, the App mints a resource-scoped JWT using `MintResourceToken`:

```go
import oa "github.com/panyam/oneauth"

token, err := oa.MintResourceToken(
    "user-42",              // userID (goes to JWT "sub" claim)
    "app_a1b2c3d4e5f6",    // appClientID (goes to "client_id" claim)
    "64-char-hex-string",   // appSecret (HS256 signing key)
    oa.AppQuota{            // embedded as custom claims
        MaxRooms:   10,
        MaxMsgRate: 30.0,
    },
    []string{"relay:connect", "relay:publish"},  // scopes
)
```

The resulting JWT contains:
```json
{
  "sub": "user-42",
  "client_id": "app_a1b2c3d4e5f6",
  "type": "access",
  "scopes": ["relay:connect", "relay:publish"],
  "max_rooms": 10,
  "max_msg_rate": 30.0,
  "iat": 1710500000,
  "exp": 1710500900
}
```

Token TTL is 15 minutes, signed with HS256.

### Step 4: User Connects to Resource Server

The user presents the JWT when connecting to the resource server:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

Or via query parameter for WebSocket connections:

```
wss://relay.example.com/ws?token=eyJhbGciOiJIUzI1NiIs...
```

### Step 5: Resource Server Validates the Token

The resource server uses `APIMiddleware` with a shared `KeyStore` to validate:

```go
middleware := &oa.APIMiddleware{
    KeyStore:        keyStore,  // shared with OneAuth server
    TokenQueryParam: "token",  // for WebSocket clients
}

mux.Handle("/ws", middleware.ValidateToken(wsHandler))
```

Validation flow:
1. Parse token without verifying signature
2. Extract `client_id` from unverified payload
3. Call `KeyStore.GetExpectedAlg(clientID)` — reject if algorithm doesn't match
4. Call `KeyStore.GetVerifyKey(clientID)` — get the signing key
5. Verify JWT signature with client-specific key
6. Store userID, scopes, and custom claims in request context

## App Registration API

The `AppRegistrar` provides a complete CRUD API for managing app registrations.

### Setup

```go
import oa "github.com/panyam/oneauth"

registrar := &oa.AppRegistrar{
    KeyStore: keyStore,                          // WritableKeyStore
    Auth:     oa.NewAPIKeyAuth("admin-secret"),  // or oa.NewNoAuth() for dev
}

mux.Handle("/", registrar.Handler())
```

### Endpoints

All endpoints require admin authentication via `X-Admin-Key` header (when using `APIKeyAuth`).

#### Register App

```http
POST /apps/register
Content-Type: application/json
X-Admin-Key: admin-secret

{
  "client_domain": "myapp.example.com",
  "signing_alg": "HS256",
  "max_rooms": 10,
  "max_msg_rate": 30.0
}
```

Returns `201 Created` with `client_id` (format: `app_<12-byte-hex>`) and `client_secret` (32-byte hex).

#### List Apps

```http
GET /apps
X-Admin-Key: admin-secret
```

Returns JSON with `"apps"` key containing an array of `AppRegistration` objects (secrets are not included).

#### Get App

```http
GET /apps/{client_id}
X-Admin-Key: admin-secret
```

Returns the app's metadata (secret not included).

#### Delete App

```http
DELETE /apps/{client_id}
X-Admin-Key: admin-secret
```

Removes the app and its key from the KeyStore. Existing tokens signed with the old secret will fail validation.

#### Rotate Secret

```http
POST /apps/{client_id}/rotate
X-Admin-Key: admin-secret
```

Generates a new `client_secret`, updates the KeyStore. Returns the new secret. Old tokens become invalid.

### Error Responses

| Status | Condition |
|--------|-----------|
| `401 Unauthorized` | Missing `X-Admin-Key` header |
| `403 Forbidden` | Wrong admin key |
| `404 Not Found` | App not found |
| `405 Method Not Allowed` | Wrong HTTP method |

## AdminAuth Interface

Pluggable authentication for the App Registration API.

```go
type AdminAuth interface {
    Authenticate(r *http.Request) error
}
```

### APIKeyAuth (Production)

Reads `X-Admin-Key` header and compares using `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

```go
auth := oa.NewAPIKeyAuth("your-secret-admin-key")

registrar := &oa.AppRegistrar{
    KeyStore: keyStore,
    Auth:     auth,
}
```

### NoAuth (Development Only)

Allows all requests without authentication. Never use in production.

```go
auth := oa.NewNoAuth()
```

## MintResourceToken

Helper function for Apps to mint resource-scoped JWTs after authenticating their users.

```go
func MintResourceToken(
    userID string,
    appClientID string,
    appSecret string,
    quota AppQuota,
    scopes []string,
) (string, error)
```

### AppQuota

```go
type AppQuota struct {
    MaxRooms   int     `json:"max_rooms,omitempty"`
    MaxMsgRate float64 `json:"max_msg_rate,omitempty"`
}
```

Quota values are embedded as custom claims in the JWT. Zero values are omitted.

### Example: App-Side Token Minting

```go
func mintTokenForUser(w http.ResponseWriter, r *http.Request) {
    // 1. Get the authenticated user from your session
    userID := getLoggedInUserID(r)

    // 2. Mint a resource token
    token, err := oa.MintResourceToken(
        userID,
        os.Getenv("APP_CLIENT_ID"),
        os.Getenv("APP_CLIENT_SECRET"),
        oa.AppQuota{MaxRooms: 10, MaxMsgRate: 30.0},
        []string{"relay:connect"},
    )
    if err != nil {
        http.Error(w, "failed to mint token", http.StatusInternalServerError)
        return
    }

    // 3. Return the token to the client
    json.NewEncoder(w).Encode(map[string]string{
        "resource_token": token,
    })
}
```

## Multi-Tenant JWT Validation

The resource server validates tokens from multiple apps using a shared `KeyStore`. See [API_AUTH.md](API_AUTH.md#multi-tenant-jwt-validation-keystore) for the full `KeyStore` interface and validation details.

Key security feature: **algorithm confusion prevention**. `KeyStore.GetExpectedAlg()` ensures an app registered with `HS256` can't send a token with `alg: none` or `alg: RS256`.

## KeyStore Implementations

All persistent implementations satisfy both `KeyStore` and `WritableKeyStore`. A shared test suite in `keystoretest/` ensures consistent behavior.

| Implementation | Location | Use Case |
|----------------|----------|----------|
| `InMemoryKeyStore` | `keystore.go` | Testing, simple deployments |
| `FSKeyStore` | `stores/fs/` | Single-node deployments |
| `GORMKeyStore` | `stores/gorm/` | Production (PostgreSQL, MySQL) |
| `GAEKeyStore` | `stores/gae/` | Google Cloud / serverless |

For store setup details, see [STORES.md](STORES.md#keystore--writablekeystore).

## Reference Server

The `cmd/oneauth-server/` directory contains a config-driven reference server that bundles `AppRegistrar`, `AdminAuth`, and KeyStore wiring.

### YAML Configuration

```yaml
server:
  port: "8080"
  host: "0.0.0.0"

keystore:
  type: "gorm"  # memory, fs, gorm, gae
  gorm:
    driver: "postgres"
    dsn: "${DATABASE_URL:-postgres://localhost/oneauth}"

admin_auth:
  type: "api-key"  # none, api-key
  api_key:
    key: "${ADMIN_API_KEY}"
```

Environment variable substitution: `${VAR_NAME}` or `${VAR_NAME:-default_value}`.

### Deployment Options

| Platform | Details |
|----------|---------|
| GAE | `go124` runtime, Secret Manager for admin key, `/_ah/health` endpoint |
| Docker | See `cmd/oneauth-server/deploy-examples/` |
| Kubernetes | See `cmd/oneauth-server/deploy-examples/` |

On GAE without a config file, the server falls back to `configFromEnv()` which reads all configuration from environment variables.

## Complete Example: Three-Service Setup

### 1. OneAuth Server (Central Auth)

```go
// cmd/oneauth-server wired with:
keyStore := gormstore.NewKeyStore(db)
adminAuth := oa.NewAPIKeyAuth(os.Getenv("ADMIN_API_KEY"))
registrar := &oa.AppRegistrar{KeyStore: keyStore, Auth: adminAuth}
mux.Handle("/", registrar.Handler())
```

### 2. App (e.g., Document Editor)

```go
// On startup: register with OneAuth server (or use pre-registered credentials)
clientID := os.Getenv("APP_CLIENT_ID")
clientSecret := os.Getenv("APP_CLIENT_SECRET")

// After authenticating a user locally:
func handleConnect(w http.ResponseWriter, r *http.Request) {
    userID := getLoggedInUserID(r)
    token, _ := oa.MintResourceToken(userID, clientID, clientSecret,
        oa.AppQuota{MaxRooms: 10}, []string{"relay:connect", "relay:publish"})

    json.NewEncoder(w).Encode(map[string]string{"resource_token": token})
}
```

### 3. Resource Server (e.g., WebSocket Relay)

```go
// Shares the same KeyStore as OneAuth server (or a read replica)
keyStore := gormstore.NewKeyStore(db)

middleware := &oa.APIMiddleware{
    KeyStore:        keyStore,
    TokenQueryParam: "token",  // for WebSocket: ws://relay?token=...
}

mux.Handle("/ws", middleware.ValidateToken(func(w http.ResponseWriter, r *http.Request) {
    userID := oa.GetUserIDFromAPIContext(r.Context())
    scopes := oa.GetScopesFromAPIContext(r.Context())
    custom := oa.GetCustomClaimsFromContext(r.Context())

    maxRooms := int(custom["max_rooms"].(float64))
    // ... proceed with scoped access
}))
```

## Security Considerations

1. **Admin key protection**: Store the admin API key in a secrets manager (e.g., GCP Secret Manager). Use `APIKeyAuth` in production, never `NoAuth`.
2. **Secret rotation**: Use `POST /apps/{client_id}/rotate` to rotate compromised secrets. Old tokens become invalid immediately.
3. **Token lifetime**: Resource tokens expire after 15 minutes. Apps should mint fresh tokens for each connection.
4. **Algorithm confusion**: `GetExpectedAlg()` prevents attacks where a token's `alg` header is manipulated.
5. **Constant-time comparison**: `APIKeyAuth` uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks on the admin key.

## Asymmetric Signing (RS256/ES256)

OneAuth supports asymmetric JWT signing alongside HS256. With asymmetric keys, apps keep their private key secret and register only the public key. Resource servers verify tokens using the public key without ever knowing the signing secret.

**Quick example** — register with RS256:

```bash
curl -X POST https://auth.example.com/apps/register \
  -H "X-Admin-Key: your-admin-key" \
  -d '{
    "client_domain": "excaliframe.com",
    "signing_alg": "RS256",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----"
  }'
```

**Quick example** — mint with asymmetric key:

```go
privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
token, err := oa.MintResourceTokenWithKey("user-42", "app_abc", privKey, quota, scopes)
```

For the full guide on key generation, algorithm selection, APIAuth configuration, key rotation, `DecodeVerifyKey`, and algorithm confusion prevention, see **[JWT_SIGNING.md](JWT_SIGNING.md)**.
