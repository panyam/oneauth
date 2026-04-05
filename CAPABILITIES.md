# OneAuth

## Version
0.0.61

## Provides
- local-authentication: Email/password authentication with signup policy, rate limiting, account lockout
- oauth-integration: OAuth providers (Google, GitHub, etc.) with PKCE
- jwt-management: Multi-tenant JWT with KeyStore, kid rotation, JWKS discovery, algorithm confusion prevention
- federated-auth: App registration, resource token minting, multi-service JWT validation
- session-management: Callback-driven session management
- email-verification: Email verification and password reset flows
- channel-linking: Multi-provider login linking
- api-key-management: API key generation and validation
- refresh-token-rotation: Refresh tokens with theft detection (family-based revocation)
- csrf-protection: Double-submit cookie CSRF protection
- multi-backend-storage: Store implementations for filesystem, GORM (PostgreSQL/MySQL), Google Datastore
- http-middleware: Auth middleware for HTTP handlers with scope enforcement
- user-identity-model: Three-layer User→Identity→Channel model
- client-credentials-grant: Machine-to-machine auth (RFC 6749 §4.4)
- token-introspection: RFC 7662 endpoint for centralized token validation
- as-discovery-server: RFC 8414 / OIDC Discovery metadata endpoint
- as-discovery-client: Client-side AS metadata discovery with fallback chain
- protected-resource-metadata: RFC 9728 resource server capability advertisement
- browser-login: OAuth authorization code + PKCE for CLI/headless clients (RFC 8252)
- token-blacklist: JWT revocation via jti-based blacklist
- encryption-at-rest: AES-256-GCM encryption of HS256 secrets via EncryptedKeyStorage
- security-headers: HSTS, CSP, X-Frame-Options middleware
- client-sdk: AuthClient with credential store, auto-refresh, browser login

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
require github.com/panyam/oneauth v0.0.61

// Local development
replace github.com/panyam/oneauth => ~/newstack/oneauth/main
```

### Key Imports
```go
import (
    "github.com/panyam/oneauth/core"
    "github.com/panyam/oneauth/apiauth"
    "github.com/panyam/oneauth/keys"
    "github.com/panyam/oneauth/client"
    "github.com/panyam/oneauth/localauth"
    "github.com/panyam/oneauth/httpauth"
    "github.com/panyam/oneauth/admin"
)
```

## Status
Mature

## Conventions
- Interface-based stores (3 backends: FS, GORM, GAE)
- Callback-driven session management
- Three-layer model (User→Identity→Channel)
- Embeddable library (not standalone service)
- Separate Go modules for heavy backends (stores/gorm, stores/gae, saml, grpc, oauth2)
- Standards-first: RFC compliance for OAuth/OIDC endpoints
- Keycloak interop tested
