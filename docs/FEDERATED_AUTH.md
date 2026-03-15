# Federated Authentication

OneAuth supports a federated authentication model where multiple Hosts (applications) register with a central auth service, obtain credentials, and mint scoped JWTs that downstream resource servers (e.g., a WebSocket relay) validate using a shared KeyStore.

## Architecture Overview

Three projects collaborate in a federated deployment:

1. **oneauth** (this repo) — shared auth library + Host Registration API
2. **Resource server** (e.g., massrelay) — validates relay-scoped JWTs using KeyStore
3. **Host app** (e.g., excaliframe) — registers as a Host, authenticates users locally, mints relay tokens

```
┌───────────────┐     1. register         ┌───────────────────┐
│   Host App    │ ───────────────────────→ │  OneAuth Server   │
│ (excaliframe) │ ←─────────────────────  │  (HostRegistrar)  │
│               │  client_id + secret     │                   │
└───────┬───────┘                         └────────┬──────────┘
        │                                          │
        │ 2. authenticate user locally             │ shared KeyStore
        │ 3. mint relay-scoped JWT                 │ (GORM, FS, GAE)
        │                                          │
        ▼                                          ▼
┌───────────────┐  4. connect with JWT    ┌───────────────────┐
│   End User    │ ───────────────────────→ │ Resource Server   │
│   (browser)   │                         │ (APIMiddleware +  │
│               │                         │  KeyStore)        │
└───────────────┘                         └───────────────────┘
```

## End-to-End Flow

### Step 1: Host Registers with OneAuth Server

The Host sends a registration request to the OneAuth server, protected by admin authentication.

```bash
curl -X POST https://auth.example.com/hosts/register \
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
  "client_id": "host_a1b2c3d4e5f6",
  "client_secret": "64-char-hex-string...",
  "client_domain": "excaliframe.com",
  "signing_alg": "HS256",
  "max_rooms": 10,
  "max_msg_rate": 30.0,
  "created_at": "2026-03-15T10:30:00Z"
}
```

The `client_secret` is stored in the `WritableKeyStore` and shared with the resource server.

### Step 2: Host Authenticates Users Locally

The Host uses its own authentication system (could be oneauth's `LocalAuth`, OAuth, or anything else) to verify the user's identity.

### Step 3: Host Mints a Relay Token

After authenticating a user, the Host mints a relay-scoped JWT using `MintRelayToken`:

```go
import oa "github.com/panyam/oneauth"

token, err := oa.MintRelayToken(
    "user-42",              // userID (goes to JWT "sub" claim)
    "host_a1b2c3d4e5f6",   // hostClientID (goes to "client_id" claim)
    "64-char-hex-string",   // hostSecret (HS256 signing key)
    oa.HostQuota{           // embedded as custom claims
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
  "client_id": "host_a1b2c3d4e5f6",
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

## Host Registration API

The `HostRegistrar` provides a complete CRUD API for managing host registrations.

### Setup

```go
import oa "github.com/panyam/oneauth"

registrar := &oa.HostRegistrar{
    KeyStore: keyStore,                          // WritableKeyStore
    Auth:     oa.NewAPIKeyAuth("admin-secret"),  // or oa.NewNoAuth() for dev
}

mux.Handle("/", registrar.Handler())
```

### Endpoints

All endpoints require admin authentication via `X-Admin-Key` header (when using `APIKeyAuth`).

#### Register Host

```http
POST /hosts/register
Content-Type: application/json
X-Admin-Key: admin-secret

{
  "client_domain": "myapp.example.com",
  "signing_alg": "HS256",
  "max_rooms": 10,
  "max_msg_rate": 30.0
}
```

Returns `201 Created` with `client_id` (format: `host_<12-byte-hex>`) and `client_secret` (32-byte hex).

#### List Hosts

```http
GET /hosts
X-Admin-Key: admin-secret
```

Returns array of `HostRegistration` objects (secrets are not included).

#### Get Host

```http
GET /hosts/{client_id}
X-Admin-Key: admin-secret
```

Returns the host's metadata (secret not included).

#### Delete Host

```http
DELETE /hosts/{client_id}
X-Admin-Key: admin-secret
```

Removes the host and its key from the KeyStore. Existing tokens signed with the old secret will fail validation.

#### Rotate Secret

```http
POST /hosts/{client_id}/rotate
X-Admin-Key: admin-secret
```

Generates a new `client_secret`, updates the KeyStore. Returns the new secret. Old tokens become invalid.

### Error Responses

| Status | Condition |
|--------|-----------|
| `401 Unauthorized` | Missing `X-Admin-Key` header |
| `403 Forbidden` | Wrong admin key |
| `404 Not Found` | Host not found |
| `405 Method Not Allowed` | Wrong HTTP method |

## AdminAuth Interface

Pluggable authentication for the Host Registration API.

```go
type AdminAuth interface {
    Authenticate(r *http.Request) error
}
```

### APIKeyAuth (Production)

Reads `X-Admin-Key` header and compares using `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

```go
auth := oa.NewAPIKeyAuth("your-secret-admin-key")

registrar := &oa.HostRegistrar{
    KeyStore: keyStore,
    Auth:     auth,
}
```

### NoAuth (Development Only)

Allows all requests without authentication. Never use in production.

```go
auth := oa.NewNoAuth()
```

## MintRelayToken

Helper function for Hosts to mint relay-scoped JWTs after authenticating their users.

```go
func MintRelayToken(
    userID string,
    hostClientID string,
    hostSecret string,
    quota HostQuota,
    scopes []string,
) (string, error)
```

### HostQuota

```go
type HostQuota struct {
    MaxRooms   int     `json:"max_rooms,omitempty"`
    MaxMsgRate float64 `json:"max_msg_rate,omitempty"`
}
```

Quota values are embedded as custom claims in the JWT. Zero values are omitted.

### Example: Host-Side Token Minting

```go
func mintTokenForUser(w http.ResponseWriter, r *http.Request) {
    // 1. Get the authenticated user from your session
    userID := getLoggedInUserID(r)

    // 2. Mint a relay token
    token, err := oa.MintRelayToken(
        userID,
        os.Getenv("HOST_CLIENT_ID"),
        os.Getenv("HOST_CLIENT_SECRET"),
        oa.HostQuota{MaxRooms: 10, MaxMsgRate: 30.0},
        []string{"relay:connect"},
    )
    if err != nil {
        http.Error(w, "failed to mint token", http.StatusInternalServerError)
        return
    }

    // 3. Return the token to the client
    json.NewEncoder(w).Encode(map[string]string{
        "relay_token": token,
    })
}
```

## Multi-Tenant JWT Validation

The resource server validates tokens from multiple hosts using a shared `KeyStore`. See [API_AUTH.md](API_AUTH.md#multi-tenant-jwt-validation-keystore) for the full `KeyStore` interface and validation details.

Key security feature: **algorithm confusion prevention**. `KeyStore.GetExpectedAlg()` ensures a host registered with `HS256` can't send a token with `alg: none` or `alg: RS256`.

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

The `cmd/oneauth-server/` directory contains a config-driven reference server that bundles `HostRegistrar`, `AdminAuth`, and KeyStore wiring.

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
registrar := &oa.HostRegistrar{KeyStore: keyStore, Auth: adminAuth}
mux.Handle("/", registrar.Handler())
```

### 2. Host Application (e.g., Document Editor)

```go
// On startup: register with OneAuth server (or use pre-registered credentials)
clientID := os.Getenv("HOST_CLIENT_ID")
clientSecret := os.Getenv("HOST_CLIENT_SECRET")

// After authenticating a user locally:
func handleConnect(w http.ResponseWriter, r *http.Request) {
    userID := getLoggedInUserID(r)
    token, _ := oa.MintRelayToken(userID, clientID, clientSecret,
        oa.HostQuota{MaxRooms: 10}, []string{"relay:connect", "relay:publish"})

    json.NewEncoder(w).Encode(map[string]string{"relay_token": token})
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
2. **Secret rotation**: Use `POST /hosts/{client_id}/rotate` to rotate compromised secrets. Old tokens become invalid immediately.
3. **Token lifetime**: Relay tokens expire after 15 minutes. Hosts should mint fresh tokens for each connection.
4. **Algorithm confusion**: `GetExpectedAlg()` prevents attacks where a token's `alg` header is manipulated.
5. **Constant-time comparison**: `APIKeyAuth` uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks on the admin key.

## Future: Asymmetric Signing (RS256/ES256)

The `KeyStore` interface already supports asymmetric keys:
- `GetVerifyKey` can return `*rsa.PublicKey` or `*ecdsa.PublicKey`
- `GetSigningKey` can return `*rsa.PrivateKey` or `*ecdsa.PrivateKey`
- Per-host algorithm choice: some hosts use HS256, others use RS256

This is planned but not yet implemented. See [NEXTSTEPS.md](NEXTSTEPS.md).
