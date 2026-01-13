# OneAuth Summary

## What is OneAuth?

OneAuth is a Go authentication library providing unified local and OAuth-based authentication with support for multiple authentication methods per user account.

## Key Features

- **Browser Authentication**: Password login, OAuth (Google, GitHub), email verification, password reset
- **API Authentication**: JWT access tokens, refresh tokens, API keys for programmatic access
- **Multi-provider**: Single account accessible via password, Google, GitHub, etc.
- **Flexible Storage**: File-based, GORM (SQL), and GAE/Datastore implementations
- **Scope-based Access**: Fine-grained permissions for API endpoints

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
│   ├── fs/           # File-based stores
│   ├── gorm/         # GORM SQL stores
│   └── gae/          # Google Datastore stores
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

## Current Version

v0.2.0 - Added API authentication with JWT, refresh tokens, API keys, and multiple store implementations.
