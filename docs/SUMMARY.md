# OneAuth Summary

## What is OneAuth?

OneAuth is a Go authentication library providing unified local and OAuth-based authentication with support for multiple authentication methods per user account.

## Key Features

- **Browser Authentication**: Password login, OAuth (Google, GitHub), email verification, password reset
- **API Authentication**: JWT access tokens, refresh tokens, API keys for programmatic access
- **Multi-provider**: Single account accessible via password, Google, GitHub, etc. with channel linking
- **Flexible Storage**: File-based, GORM (SQL), and GAE/Datastore implementations
- **Scope-based Access**: Fine-grained permissions for API endpoints
- **Multi-tenant JWT**: KeyStore interface for per-client signing keys, custom claims, algorithm confusion prevention, asymmetric signing (RS256/ES256)
- **Policy-Based Validation**: Configurable signup requirements (SignupPolicy)
- **Username Support**: Optional username uniqueness with username-based login
- **App Registration API**: AdminAuth interface (APIKeyAuth, NoAuth), AppRegistrar HTTP handler for App CRUD, MintResourceToken for resource-scoped JWTs
- **Client SDK**: AuthClient with CredentialStore, HTTPClient wrapper with automatic token refresh on 401
- **Reference Server**: Config-driven server in `cmd/oneauth-server/`, deployable to GAE, Docker, and Kubernetes
- **Federated Auth Demo**: 6-service Docker Compose demo (oneauth-server, 2 app services, 2 resource servers, PostgreSQL) in `demo/`

## Architecture

Three-layer data model separating concerns:

1. **User**: Account with profile data
2. **Identity**: Contact method (email/phone) with verification status
3. **Channel**: Auth mechanism (local, google, github) with credentials

## Package Structure

```
oneauth/
├── *.go                  # Core types and handlers
├── stores/
│   ├── fs/               # File-based stores (server)
│   ├── gorm/             # GORM SQL stores
│   └── gae/              # Google Datastore stores
├── client/               # Client SDK for token management
│   └── stores/fs/        # File-based credential store
├── cmd/oneauth-server/   # Reference server (config-driven, GAE/Docker/K8s)
├── cmd/demo-hostapp/     # Demo app (DrawApp/ChatApp)
├── cmd/demo-resource-server/  # Demo resource server (JWT validation service)
├── demo/                 # Docker Compose demo (6 services: auth, 2 apps, 2 resource servers, DB)
├── keystoretest/         # Shared KeyStore test suite
├── tests/integration/    # Integration tests (GAE + demo stack)
├── grpc/                 # gRPC utilities
├── oauth2/               # OAuth2 providers
└── saml/                 # SAML support
```

## Quick Start

```go
import (
    "github.com/panyam/oneauth"
    "github.com/panyam/oneauth/stores/fs"
)

// Browser auth
localAuth := &oneauth.LocalAuth{...}
mux.Handle("/auth/login", localAuth)

// API auth
apiAuth := &oneauth.APIAuth{...}
mux.Handle("/api/login", http.HandlerFunc(apiAuth.HandleLogin))

// Protect endpoints with APIMiddleware
middleware := &oneauth.APIMiddleware{
    TokenQueryParam: "token",  // optional: accept token as query param
    // ...
}
mux.Handle("/api/protected", middleware.ValidateToken(handler))

// Extract custom claims in handlers
claims := oneauth.GetCustomClaimsFromContext(r.Context())
```

### Client SDK

```go
import (
    "github.com/panyam/oneauth/client"
    "github.com/panyam/oneauth/client/stores/fs"
)

// Create credential store
store, _ := fs.NewFSCredentialStore("", "myapp")

// Create auth client
authClient := client.NewAuthClient("https://api.example.com", store)

// Login
authClient.Login("user@example.com", "password", "read write")

// Use authenticated HTTP client (auto-refresh on 401)
resp, _ := authClient.HTTPClient().Get("https://api.example.com/resource")
```

## Unified Auth for HTTP Handlers

The `Middleware` can validate both session-based auth (for browsers) and Bearer tokens (for API/CLI clients) through a unified interface:

```go
// Wire up APIAuth's JWT validation to Middleware
apiAuth := &oneauth.APIAuth{
    JWTSecretKey: "secret",
    JWTIssuer:    "myapp",
    // ...
}
oneauth.Middleware.VerifyToken = apiAuth.VerifyTokenFunc()

// Now GetLoggedInUserId checks both session AND Bearer token
userID := middleware.GetLoggedInUserId(r)  // Works for browser and API clients
```

The `Middleware.GetLoggedInUserId()` now:
1. Checks request context (previously set by ExtractUser)
2. Checks session (for browser clients)
3. Checks Authorization header for Bearer tokens (for API/CLI clients)

## Channel Linking

OneAuth supports linking multiple auth methods to the same account:

```go
// OAuth callback automatically links to existing user with same email
ensureUser := oneauth.NewEnsureAuthUserFunc(config)

// OAuth-only user can add password later
oneauth.LinkLocalCredentials(config, userID, "username", "password", email)

// Password user can link Google account
oneauth.StartLinkOAuth(r, userID)  // In "Link Google" handler
// Then in OAuth callback:
oneauth.HandleLinkOAuthCallback(config, linkingUserID, "google", userInfo, w, r)
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | High-level overview and design principles |
| [BROWSER_AUTH.md](BROWSER_AUTH.md) | Browser-based auth (LocalAuth, OAuth, sessions, validation) |
| [API_AUTH.md](API_AUTH.md) | API auth (JWT, refresh tokens, API keys, KeyStore) |
| [FEDERATED_AUTH.md](FEDERATED_AUTH.md) | Federated auth (AppRegistrar, MintResourceToken, AdminAuth) |
| [JWT_SIGNING.md](JWT_SIGNING.md) | JWT signing algorithms (HS256/RS256/ES256), key management, crypto helpers |
| [AUTH_FLOWS.md](AUTH_FLOWS.md) | Detailed decision trees, user journeys, edge cases |
| [CLIENT_SDK.md](CLIENT_SDK.md) | Client SDK for CLI/programmatic access |
| [STORES.md](STORES.md) | Store interfaces and implementations |
| [DEMOS.md](DEMOS.md) | Runnable demos, scenarios, and production vs. demo comparison |

## Current Version

- **v0.0.35**: JWKS endpoint for federated public key discovery (#7). `JWKSHandler` serves `/.well-known/jwks.json`, `JWKSKeyStore` fetches keys from remote JWKS URL, `utils/jwk.go` JWK conversion utilities. Demo resource server supports `JWKS_URL` as alternative to shared database.
- **v0.0.34**: Asymmetric JWT signing (RS256/ES256). `MintResourceTokenWithKey`, `APIAuth.JWTSigningKey`/`JWTVerifyKey`, `AppRegistrar` public key registration, `utils/crypto_helpers.go`, keystoretest asymmetric suite, pre-push hook.
- **v0.0.33**: Federated auth demo with guided UI, devloop live-reload, CORS, credential recovery, per-page template routing. Renamed Host/Relay to App/Resource Server throughout.
- **v0.0.32**: APIMiddleware enhancements (TokenQueryParam, GetCustomClaimsFromContext).
- **v0.0.31**: App Registration API (AdminAuth, AppRegistrar, MintResourceToken). Config-driven reference server (`cmd/oneauth-server/`).
- **v0.0.30**: WritableKeyStore interface. Persistent KeyStore backends (GORM, FS, GAE). Shared test suite in `keystoretest/`.
- **v0.0.29**: CustomClaimsFunc, KeyStore interface, InMemoryKeyStore, multi-tenant JWT validation with algorithm confusion prevention.
- **v0.0.28**: Optimistic locking (Version, UpdatedAt) on Identity/Channel. ExpiresAt on Channel for OAuth token expiry tracking.
