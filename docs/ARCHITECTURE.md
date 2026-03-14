# OneAuth Architecture

## Overview

OneAuth is a Go authentication library that provides unified local and OAuth-based authentication, multi-tenant JWT management, and federated auth for distributed services. It's designed as an embeddable library (not a standalone service) that integrates directly into Go applications. A reference server (`cmd/oneauth-server/`) is provided for standalone deployment.

**Go version**: 1.24.0+

## Core Design Principles

1. **Separation of Concerns**: Users, Identities, and Channels as distinct layers
2. **Framework Agnostic**: Works with net/http and any router
3. **Storage Agnostic**: Interface-based stores with multiple implementations
4. **Callback-Based**: Application controls session management, email delivery, etc.

## Three-Layer Data Model

```
┌─────────────────────────────────────────────────────────┐
│                         User                            │
│  - Unique account in the system                         │
│  - Contains profile data                                │
│  - Has multiple identities                              │
└────────────────────────┬────────────────────────────────┘
                         │
           ┌─────────────┼──────────────┐
           │             │              │
           ▼             ▼              ▼
┌──────────────┐ ┌──────────────┐  ┌──────────────┐
│   Identity   │ │   Identity   │  │   Identity   │
│  email:...   │ │  phone:...   │  │  email:...   │
│  (verified)  │ │ (unverified) │  │  (verified)  │
└──────┬───────┘ └──────────────┘  └──────┬───────┘
       │                                  │
       │         ┌────────────────────────┤
       │         │                        │
       ▼         ▼                        ▼
┌──────────┐ ┌──────────┐          ┌──────────┐
│ Channel  │ │ Channel  │          │ Channel  │
│  local   │ │  google  │          │  github  │
│(password)│ │ (oauth)  │          │ (oauth)  │
└──────────┘ └──────────┘          └──────────┘
```

### User
- Unique account identified by user ID
- Contains profile information (name, avatar, etc.)
- Application-controlled creation and management

### Identity
- Contact method (email, phone)
- Has verification status
- Links to user account
- Shared across authentication channels

### Channel
- Authentication mechanism (local, google, github)
- Stores provider-specific credentials
- Password hash for local, OAuth tokens for OAuth providers
- Multiple channels can point to the same user via shared email identity

### UsernameStore (Optional)
- Separate store for username → userID mapping
- Enables username uniqueness enforcement
- Supports username-based login (in addition to email)

## Authentication Modes

OneAuth supports three authentication modes, each targeting a different client type:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Authentication Modes                            │
├─────────────────────┬───────────────────────┬───────────────────────────┤
│   Browser Auth      │   API Auth            │   Federated Auth          │
│   (LocalAuth)       │   (APIAuth)           │   (HostRegistrar +        │
│                     │                       │    MintRelayToken)        │
│   Form login/signup │   JWT access tokens   │   Host registers,        │
│   Email verify      │   Refresh tokens      │   mints scoped JWTs,     │
│   Password reset    │   API keys            │   resource server         │
│   Session cookies   │   Scope enforcement   │   validates via KeyStore  │
└─────────────────────┴───────────────────────┴───────────────────────────┘
```

### Browser Authentication (LocalAuth)

```
┌──────────┐                 ┌───────────┐                ┌──────────────┐
│  Browser │ ── POST ──────→ │ LocalAuth │ ── callback ─→ │  HandleUser  │
│          │    /auth/login   │           │                │  (app-owned) │
│          │ ←─ cookie ────  │           │                │  set session │
└──────────┘                 └───────────┘                └──────────────┘
```

- Form-based login/signup
- Email verification flow
- Password reset flow (JSON + redirect modes)
- Session management via callback

### API Authentication (APIAuth)

```
┌──────────┐   POST /api/login    ┌──────────┐   JWT + refresh token
│  Client  │ ───────────────────→ │ APIAuth  │ ──────────────────────→ Client stores tokens
│ (SPA,    │                      │          │
│  mobile, │   GET /api/resource  ├──────────┤
│  CLI)    │ ───────────────────→ │ APIMid-  │ ── validates JWT ──→ Handler (userID in ctx)
│          │   Authorization:     │ dleware  │
│          │   Bearer <jwt>       │          │
│          │   — or —             │          │
│          │   ?token=<jwt>       │          │
└──────────┘                      └──────────┘
```

- JWT access tokens (stateless, 15 min)
- Refresh tokens (database, 7 days, rotating)
- API keys (long-lived, for automation)
- Scope-based access control
- Custom claims injection + extraction

## Token Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Token Lifecycle                                  │
│                                                                            │
│   Login                                                                    │
│     │                                                                      │
│     ▼                                                                      │
│   ┌─────────────────┐    ┌──────────────────┐                             │
│   │  Access Token   │    │  Refresh Token    │                             │
│   │  (JWT, 15 min)  │    │  (opaque, 7 days) │                             │
│   └────────┬────────┘    └────────┬─────────┘                             │
│            │                      │                                        │
│            ▼                      ▼                                        │
│   API requests with        On access token expiry:                        │
│   Authorization: Bearer    POST /api/login {grant_type: refresh_token}    │
│            │                      │                                        │
│            │                      ▼                                        │
│            │              ┌──────────────────┐                             │
│            │              │  Rotate: old      │                             │
│            │              │  revoked, new     │                             │
│            │              │  refresh + access │                             │
│            │              │  tokens issued    │                             │
│            │              └──────────────────┘                             │
│            │                      │                                        │
│            │                      ▼                                        │
│            │              Theft detection:                                 │
│            │              reuse of old token                               │
│            │              → revoke entire family                           │
│            │                                                               │
│   ┌────────┴────────┐                                                     │
│   │   API Key       │  Long-lived, prefixed oa_                           │
│   │   (bcrypt hash) │  For CI/CD, scripts, automation                     │
│   └─────────────────┘                                                     │
└────────────────────────────────────────────────────────────────────────────┘
```

### Access Tokens (JWT)
- Short-lived (15 min default)
- Stateless validation
- Contains: user ID, scopes, issuer, audience, expiry, custom claims
- Signed with HS256 (asymmetric RS256/ES256 planned)

### Refresh Tokens
- Long-lived (7 days default)
- Stored in database
- Rotated on each use
- Family tracking for theft detection
- Revocable

### API Keys
- Long-lived (optional expiry)
- Stored as bcrypt hash
- Prefixed with `oa_` for identification
- User-manageable

## Multi-Tenant JWT and KeyStore

For federated systems where multiple Hosts mint JWTs verified by a shared resource server, oneauth supports multi-tenant signing key management.

### KeyStore Interface

```go
type KeyStore interface {
    GetVerifyKey(clientID string) (any, error)    // []byte for HMAC, crypto.PublicKey for asymmetric
    GetSigningKey(clientID string) (any, error)
    GetExpectedAlg(clientID string) (string, error)  // algorithm confusion prevention
}
```

### WritableKeyStore Interface

Extends `KeyStore` with mutation operations for dynamic key management:

```go
type WritableKeyStore interface {
    KeyStore
    RegisterKey(clientID string, key any, alg string) error
    DeleteKey(clientID string) error
    ListKeys() ([]string, error)
}
```

### Custom Claims

`APIAuth.CustomClaimsFunc` injects custom claims into JWTs at minting time (e.g., `client_id`, `max_rooms`). Standard claims (`sub`, `iss`, `aud`, `exp`, `iat`, `type`, `scopes`) cannot be overridden.

`APIAuth.ValidateAccessTokenFull()` returns custom claims separately from standard claims for downstream extraction.

### Multi-Tenant Validation Flow

```
Incoming JWT
     │
     ▼
┌────────────────────────────┐
│ 1. Parse unverified claims │
│    extract client_id       │
└────────────┬───────────────┘
             │
             ▼
┌────────────────────────────┐     ┌──────────────────┐
│ 2. KeyStore.GetExpectedAlg │────→│ Algorithm match?  │── no ──→ 401 Reject
│    (client_id)             │     │ (HS256? RS256?)   │
└────────────────────────────┘     └────────┬─────────┘
                                            │ yes
                                            ▼
                                   ┌──────────────────┐
                                   │ 3. KeyStore.     │
                                   │    GetVerifyKey  │
                                   │    (client_id)   │
                                   └────────┬─────────┘
                                            │
                                            ▼
                                   ┌──────────────────┐
                                   │ 4. Verify JWT    │── fail ──→ 401 Reject
                                   │    signature     │
                                   └────────┬─────────┘
                                            │ pass
                                            ▼
                                   ┌──────────────────┐
                                   │ 5. Store in ctx: │
                                   │  - userID        │
                                   │  - scopes        │
                                   │  - custom claims │
                                   └──────────────────┘
```

When `KeyStore` is nil, falls back to single `JWTSecretKey` (backwards-compatible).

### APIMiddleware Enhancements

- **`TokenQueryParam`**: When set (e.g., `"token"`), the middleware extracts JWTs from the query parameter in addition to the `Authorization` header. This supports WebSocket clients and other contexts where setting HTTP headers is not possible.
- **`GetCustomClaimsFromContext(ctx)`**: Extracts custom claims that were stored in the request context by the middleware during validation.
- **`validateRequest` / `validateJWT`**: Both return custom claims alongside standard claims, making them available to downstream handlers.

### KeyStore Implementations

- **`InMemoryKeyStore`** — thread-safe map, for testing and simple deployments
- **`FSKeyStore`** (`keystores/fs/`) — file-system-based, JSON on disk, suitable for single-node deployments
- **`GORMKeyStore`** (`keystores/gorm/`) — SQL-backed via GORM, production-ready
- **`GAEKeyStore`** (`keystores/gae/`) — Google Cloud Datastore, serverless-friendly

All persistent implementations satisfy both `KeyStore` and `WritableKeyStore`. A shared test suite in `keystoretest/` ensures consistent behavior across all implementations.

## Store Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Store Interfaces                       │
│  UserStore | IdentityStore | ChannelStore | TokenStore       │
│  RefreshTokenStore | APIKeyStore | UsernameStore (opt)       │
│  KeyStore | WritableKeyStore (multi-tenant JWT)              │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   stores/fs   │   │  stores/gorm  │   │  stores/gae   │
│  File-based   │   │  SQL (GORM)   │   │  Datastore    │
│  Development  │   │  Production   │   │  Google Cloud │
└───────────────┘   └───────────────┘   └───────────────┘
```

### File-Based Stores (stores/fs)
- JSON files on disk
- Suitable for development and <1000 users
- Atomic writes for consistency
- No external dependencies

### GORM Stores (stores/gorm)
- SQL databases (PostgreSQL, MySQL, SQLite)
- Production-ready
- Auto-migration support
- Connection pooling via GORM

### GAE Stores (stores/gae)
- Google Cloud Datastore
- Namespace support for multi-tenancy
- Serverless-friendly
- Automatic scaling

## Federated Auth and Host Registration

OneAuth supports a federated authentication model where multiple Hosts (applications) register with a central auth service, obtain credentials, and mint scoped JWTs that downstream resource servers validate using a shared KeyStore.

### Architecture

```
┌───────────┐     register      ┌──────────────────┐
│  Host App │ ─────────────────→│  OneAuth Server   │
│           │ ←───────────────  │  (HostRegistrar)  │
│           │  client_id/secret │                   │
└─────┬─────┘                   └────────┬──────────┘
      │                                  │
      │ authenticate user                │ shared KeyStore
      │ mint relay-scoped JWT            │
      ▼                                  ▼
┌───────────┐    validate JWT   ┌──────────────────┐
│  End User │ ─────────────────→│ Resource Server   │
│  (client) │                   │ (APIMiddleware +  │
│           │                   │  KeyStore)        │
└───────────┘                   └──────────────────┘
```

### Key Components

- **`AdminAuth` interface**: Pluggable admin authentication for the registration API. Implementations include `APIKeyAuth` (bearer token) and `NoAuth` (for development).
- **`HostRegistrar`**: Embeddable HTTP handler providing Host CRUD operations — register, list, get, delete, and rotate secret. Stores host credentials in the backing `WritableKeyStore`.
- **`MintRelayToken`**: Helper function for minting relay-scoped JWTs. Hosts call this after authenticating their users to produce tokens that downstream services can validate.

### Flow

1. Host registers with the OneAuth server → receives `client_id` + `client_secret`
2. Host authenticates its users (via its own login flow)
3. Host calls `MintRelayToken` to produce a scoped JWT signed with its `client_secret`
4. End user presents the JWT to the downstream resource server
5. Resource server validates via `APIMiddleware` + shared `KeyStore` (looks up the signing key by `client_id`)

### Reference Server (`cmd/oneauth-server/`)

A config-driven YAML reference server that bundles `HostRegistrar`, `AdminAuth`, and KeyStore wiring. Deployable on:
- Google App Engine (GAE)
- Docker / Docker Compose
- Kubernetes

## Security Architecture

### Password Security
- bcrypt hashing with cost 10
- No plain-text storage
- Constant-time comparison

### Token Security
- Cryptographically secure random generation (32 bytes)
- Single-use verification tokens
- Expiry enforcement
- Lazy cleanup on access

### JWT Security
- HS256 signing (asymmetric algorithms planned)
- Audience and issuer validation
- Expiry validation
- Secret key rotation support
- Algorithm confusion prevention via `GetExpectedAlg`

### Refresh Token Security
- Rotation on use
- Family-based theft detection
- Immediate revocation capability
- Device tracking support

## Request Flow

### Browser Login
```
1. POST /auth/login (email, password)
2. LocalAuth.ServeHTTP
3. ValidateCredentials callback
4. Channel lookup → password verification
5. Identity lookup → user lookup
6. HandleUser callback → session creation
```

### API Login
```
1. POST /api/login (grant_type=password, username, password)
2. APIAuth.HandleLogin
3. ValidateCredentials callback
4. Generate JWT access token
5. Create refresh token in store
6. Return token pair
```

### API Request
```
1. GET /api/resource (Authorization: Bearer <jwt>)
   — or: GET /api/resource?token=<jwt> (when TokenQueryParam is set)
2. APIMiddleware.ValidateToken
3. Parse and validate JWT (returns standard + custom claims)
4. Extract user ID and scopes
5. Add to request context (including custom claims)
6. Call handler
```

### Token Refresh
```
1. POST /api/login (grant_type=refresh_token, refresh_token)
2. APIAuth.HandleLogin
3. Get refresh token from store
4. Rotate token (invalidate old, create new)
5. Generate new JWT
6. Return new token pair
```

## Scope Model

```go
const (
    ScopeRead    = "read"     // Read user data
    ScopeWrite   = "write"    // Modify user data
    ScopeProfile = "profile"  // Access profile info
    ScopeOffline = "offline"  // Enable refresh tokens
)
```

### Scope Resolution
1. User logs in, requests scopes
2. GetUserScopes callback returns allowed scopes
3. Intersection granted to token
4. Middleware validates endpoint requires subset

## Channel Linking

Multiple authentication channels can point to the same user via shared email identity:

```
User (id: abc123)
├── Identity: email → user@example.com
├── Channel: local   → email:user@example.com (password_hash)
├── Channel: google  → email:user@example.com (oauth profile)
└── Channel: github  → email:user@example.com (oauth profile)
```

### Linking Flows

1. **OAuth to Existing User**: OAuth callback finds existing identity by email → links channel
2. **Add Password to OAuth User**: `LinkLocalCredentials()` creates local channel
3. **Add OAuth to Password User**: `HandleLinkOAuthCallback()` creates OAuth channel

### Profile Tracking

User profile tracks linked channels: `profile["channels"] = ["local", "google", "github"]`

## Extension Points

### SignupPolicy
```go
localAuth.SignupPolicy = &oneauth.SignupPolicy{
    RequireUsername:       true,
    RequireEmail:          true,
    MinPasswordLength:     12,
    UsernamePattern:       `^[a-z][a-z0-9_]{2,19}$`,
}
```

### Custom Error Handlers
```go
localAuth.OnSignupError = func(err *AuthError, w http.ResponseWriter, r *http.Request) bool {
    session.SetFlash(r, "error", err.Message)
    http.Redirect(w, r, "/signup", http.StatusSeeOther)
    return true
}
```

### Custom Validation (Legacy)
```go
localAuth.ValidateSignup = func(creds *Credentials) error {
    // Custom rules
}
```

### Custom Scope Resolution
```go
apiAuth.GetUserScopes = func(userID string) ([]string, error) {
    // Lookup roles, permissions, etc.
}
```

### Custom Email Sender
```go
type SMTPSender struct{}
func (s *SMTPSender) SendVerificationEmail(to, link string) error
func (s *SMTPSender) SendPasswordResetEmail(to, link string) error
```

### Custom Stores
Implement the store interfaces for any database.

## Client SDK (`client/`)

For CLI tools and programmatic clients consuming oneauth-protected APIs:

```
┌─────────────────────────────────────────────────────────┐
│                     AuthClient                          │
│  - Login/Logout                                         │
│  - Automatic token refresh                              │
│  - HTTPClient() returns authenticated client            │
└─────────────────────────────┬───────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌────────────────┐
│CredentialStore│    │ AuthTransport │    │RefreshTransport│
│  (interface)  │    │  (Bearer hdr) │    │  (401 retry)   │
└───────┬───────┘    └───────────────┘    └────────────────┘
        │
        ▼
┌────────────────┐
│client/stores/fs│
│ JSON file      │
│~/.config/<app> │
└────────────────┘
```

### Components

- **`AuthClient`**: High-level client for login, logout, and obtaining authenticated HTTP clients. Manages token lifecycle.
- **`CredentialStore` interface**: Pluggable credential persistence. `Save`, `Load`, `Clear` operations.
- **`HTTPClient`**: Returns an `*http.Client` with authentication transport wired in.
- **`AuthTransport`**: `http.RoundTripper` that injects `Authorization: Bearer <token>` headers on every request.
- **`RefreshTransport`**: `http.RoundTripper` that intercepts 401 responses, refreshes the access token, and retries the original request.
- **`client/stores/fs/`**: File-based `CredentialStore` implementation using JSON on disk (e.g., `~/.config/<app>/credentials.json`).

### Features
- **Automatic refresh**: On 401 or before token expiry
- **Thread-safe**: Mutex protects concurrent access
- **Configurable**: Custom HTTP client, transport, token endpoint

## Positioning

OneAuth differentiates from alternatives by being:

- **Embeddable library** (not a service to run)
- **Go-native** (not language-agnostic)
- **Simple model** (User → Identity → Channel)
- **Multiple store options** (file, SQL, NoSQL)
- **Callback-based** (app controls sessions)
- **Federated-ready** (multi-tenant KeyStore, host registration, relay token minting)

Closest alternatives:
- `go-pkgz/auth` - Similar middleware focus, less flexible model
- `Ory Kratos` - Full IAM platform, more complex
- `Authelia` - Reverse proxy companion, different architecture
