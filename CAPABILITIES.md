# OneAuth

## Version
0.0.32

## Provides
- local-authentication: Email/password authentication
- oauth-integration: OAuth providers (Google, GitHub, etc.)
- jwt-management: Multi-tenant JWT with KeyStore, kid rotation, JWKS discovery
- federated-auth: Federated authentication support
- session-management: Callback-driven session management
- email-verification: Email verification and password reset flows
- channel-linking: Multi-provider login linking
- api-key-management: API key generation and validation
- refresh-token-rotation: Refresh tokens with theft detection
- csrf-protection: Double-submit cookie CSRF protection
- multi-backend-storage: Store implementations for filesystem, GORM, Google Datastore
- http-middleware: Auth middleware for HTTP handlers
- user-identity-model: Three-layer User→Identity→Channel model

## Module
github.com/panyam/oneauth

## Location
newstack/oneauth/main

## Stack Dependencies
- goutils (github.com/panyam/goutils)

## Integration

### Go Module
```go
// go.mod
require github.com/panyam/oneauth 0.0.32

// Local development
replace github.com/panyam/oneauth => ~/newstack/oneauth/main
```

### Key Imports
```go
import "github.com/panyam/oneauth/auth"
```

## Status
Mature

## Conventions
- Interface-based stores
- Callback-driven session management
- Three-layer model (User→Identity→Channel)
- Embeddable library (not standalone service)
