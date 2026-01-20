# OneAuth Summary

## What is OneAuth?

OneAuth is a Go authentication library providing unified local and OAuth-based authentication with support for multiple authentication methods per user account.

## Key Features

- **Browser Authentication**: Password login, OAuth (Google, GitHub), email verification, password reset
- **API Authentication**: JWT access tokens, refresh tokens, API keys for programmatic access
- **Multi-provider**: Single account accessible via password, Google, GitHub, etc. with channel linking
- **Flexible Storage**: File-based, GORM (SQL), and GAE/Datastore implementations
- **Scope-based Access**: Fine-grained permissions for API endpoints
- **Policy-Based Validation**: Configurable signup requirements (SignupPolicy)
- **Username Support**: Optional username uniqueness with username-based login

## Architecture

Three-layer data model separating concerns:

1. **User**: Account with profile data
2. **Identity**: Contact method (email/phone) with verification status
3. **Channel**: Auth mechanism (local, google, github) with credentials

## Package Structure

```
oneauth/
├── *.go              # Core types and handlers
├── stores/
│   ├── fs/           # File-based stores (server)
│   ├── gorm/         # GORM SQL stores
│   └── gae/          # Google Datastore stores
├── client/           # Client SDK for token management
│   └── stores/fs/    # File-based credential store
├── grpc/             # gRPC utilities
├── oauth2/           # OAuth2 providers
└── saml/             # SAML support (planned)
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

// Protect endpoints
middleware := &oneauth.APIMiddleware{...}
mux.Handle("/api/protected", middleware.ValidateToken(handler))
```

### Client SDK (for CLI/programmatic access)

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

## Current Version

v0.0.28 - Added optimistic locking fields (`Version`, `UpdatedAt`) to Identity and Channel models. Added `ExpiresAt` field to Channel for tracking when OAuth tokens or auth sessions need re-authentication. Added `IsExpired()` helper method to Channel. Updated all store implementations (GAE, FS, GORM).
