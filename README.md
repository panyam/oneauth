# OneAuth

A Go authentication library providing unified local and OAuth-based authentication with support for multiple authentication methods per user account.

## Features

- **Unified authentication** — Password and OAuth through a single interface
- **Multi-provider support** — One account accessible via password, Google, GitHub, etc.
- **API authentication** — JWT access tokens, refresh tokens, API keys
- **Multi-tenant JWT** — KeyStore interface for per-client signing keys with algorithm confusion prevention
- **Federated auth** — App registration, resource-scoped token minting, custom claims
- **Flexible storage** — File-based, GORM (SQL), and GAE/Datastore implementations
- **Client SDK** — Token management, auto-refresh, credential persistence for CLI tools
- **gRPC support** — Auth context utilities and interceptors

## Quick Start

```bash
go get github.com/panyam/oneauth
```

```go
import (
    "github.com/panyam/oneauth"
    "github.com/panyam/oneauth/stores/fs"
)

// Initialize stores
storagePath := "/path/to/storage"
userStore := fs.NewFSUserStore(storagePath)
identityStore := fs.NewFSIdentityStore(storagePath)
channelStore := fs.NewFSChannelStore(storagePath)
tokenStore := fs.NewFSTokenStore(storagePath)

// Create authentication callbacks
createUser := oneauth.NewCreateUserFunc(userStore, identityStore, channelStore)
validateCreds := oneauth.NewCredentialsValidator(identityStore, channelStore, userStore)

// Configure local authentication
localAuth := &oneauth.LocalAuth{
    CreateUser:          createUser,
    ValidateCredentials: validateCreds,
    EmailSender:         &oneauth.ConsoleEmailSender{},
    TokenStore:          tokenStore,
    BaseURL:             "https://yourapp.com",
    HandleUser:          yourSessionHandler,
}

// Set up HTTP routes
mux := http.NewServeMux()
mux.Handle("/auth/login", localAuth)
mux.Handle("/auth/signup", http.HandlerFunc(localAuth.HandleSignup))
```

See [Getting Started](docs/GETTING_STARTED.md) for the full setup guide.

## Architecture

OneAuth separates authentication into three layers:

```
User: john@example.com
├── Identity: john@example.com (verified)
├── Channel: local    (password hash)
├── Channel: google   (OAuth tokens)
└── Channel: github   (OAuth tokens)
```

- **User** — A unique account with profile information
- **Identity** — An email or phone number with verification status (shared across channels)
- **Channel** — An authentication mechanism storing provider-specific credentials

Verifying an email through any channel (e.g., Google OAuth) verifies it for all channels.

See [Architecture](docs/ARCHITECTURE.md) for design decisions, data model diagrams, and token lifecycle.

## API Authentication

Protect API endpoints with JWT middleware:

```go
middleware := &oneauth.APIMiddleware{
    KeyStore:        keyStore,        // multi-tenant (per-client keys)
    TokenQueryParam: "token",         // ?token= fallback for WebSocket clients
}

mux.Handle("/api/data", middleware.ValidateToken(handler))
mux.Handle("/api/write", middleware.RequireScopes("write")(handler))
mux.Handle("/api/public", middleware.Optional(handler))

// Access claims in handlers
userID := oneauth.GetUserIDFromAPIContext(r.Context())
custom := oneauth.GetCustomClaimsFromContext(r.Context())
```

See [API Authentication](docs/API_AUTH.md) for JWT lifecycle, custom claims, multi-tenant validation, and middleware configuration.

## Federated Auth (App Registration)

For systems where multiple applications register and mint scoped JWTs:

```go
// Resource server validates tokens from any registered app
keyStore := gorm.NewGORMKeyStore(db)
middleware := &oneauth.APIMiddleware{KeyStore: keyStore}

// Apps register via admin API and mint tokens for their users
token, err := oneauth.MintResourceToken(clientID, clientSecret, userID, scopes, customClaims)
```

See [Architecture — Federated Auth](docs/ARCHITECTURE.md#federated-authentication) for the full flow.

## Store Implementations

| Implementation | Package | Use Case |
|---------------|---------|----------|
| File-based | `stores/fs` | Development, < 1000 users |
| GORM (SQL) | `stores/gorm` | PostgreSQL, MySQL, SQLite |
| GAE/Datastore | `stores/gae` | Google Cloud deployments |

All stores implement the same interfaces: `UserStore`, `IdentityStore`, `ChannelStore`, `TokenStore`, `RefreshTokenStore`, `APIKeyStore`, `KeyStore`.

See [Stores](docs/STORES.md) for interface definitions and usage examples.

## Client SDK

For CLI tools and programmatic clients:

```go
import (
    "github.com/panyam/oneauth/client"
    "github.com/panyam/oneauth/client/stores/fs"
)

store, _ := fs.NewFSCredentialStore("", "myapp")
authClient := client.NewAuthClient("https://api.example.com", store)
authClient.Login("user@example.com", "password", "read write")

// Auto-refresh on 401 or before expiry
resp, _ := authClient.HTTPClient().Get("https://api.example.com/resource")
```

## Documentation

### Guides

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/GETTING_STARTED.md) | Installation, store setup, first auth flow |
| [API Authentication](docs/API_AUTH.md) | JWT middleware, custom claims, multi-tenant validation |
| [Browser Authentication](docs/BROWSER_AUTH.md) | OAuth flows, channel linking, session management |
| [gRPC Integration](docs/GRPC.md) | Context utilities, auth interceptors |
| [Stores](docs/STORES.md) | Store interfaces, implementations, KeyStore |
| [Testing](docs/TESTING.md) | Test patterns, security best practices |

### Reference

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Design decisions, data model, token lifecycle, federated auth |
| [Auth Flows](docs/AUTH_FLOWS.md) | Login/signup decision trees, user journeys |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Index of all developer documentation |
| [User Guide](docs/USER_GUIDE.md) | End-user documentation |
| [Release Notes](docs/RELEASE_NOTES.md) | Version history and changelog |
| [API Docs](https://pkg.go.dev/github.com/panyam/oneauth) | Generated godoc reference |

## Requirements

- Go 1.21+
- `golang.org/x/crypto/bcrypt` — password hashing
- `github.com/golang-jwt/jwt/v5` — JWT tokens
- `golang.org/x/oauth2` — OAuth providers (optional)
- `gorm.io/gorm` — GORM stores (optional)
- `cloud.google.com/go/datastore` — GAE stores (optional)

## License

See LICENSE file for terms and conditions.
