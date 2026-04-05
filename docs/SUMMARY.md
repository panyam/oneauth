# OneAuth Summary

## What is OneAuth?

OneAuth is a Go authentication library providing unified local and OAuth-based authentication with support for multiple authentication methods per user account.

## Key Features

- **Browser Authentication**: Password login, OAuth (Google, GitHub), email verification, password reset
- **API Authentication**: JWT access tokens, refresh tokens, API keys for programmatic access
- **Multi-provider**: Single account accessible via password, Google, GitHub, etc. with channel linking
- **Flexible Storage**: File-based, GORM (SQL), and GAE/Datastore implementations
- **Scope-based Access**: Fine-grained permissions for API endpoints
- **Multi-tenant JWT**: KeyStorage/KeyLookup interfaces for per-client signing keys, kid (Key ID) in all JWTs for JWKS-based discovery, key rotation with grace period (KidStore), custom claims, algorithm confusion prevention, asymmetric signing (RS256/ES256), HS256 secret encryption at rest (AES-256-GCM via EncryptedKeyStorage)
- **Policy-Based Validation**: Configurable signup requirements (SignupPolicy)
- **Username Support**: Optional username uniqueness with username-based login
- **App Registration API**: AdminAuth interface (APIKeyAuth, NoAuth), AppRegistrar HTTP handler for App CRUD, MintResourceToken for resource-scoped JWTs
- **Protected Resource Metadata**: RFC 9728 — resource servers advertise capabilities at `/.well-known/oauth-protected-resource` for client auto-discovery
- **Client SDK**: AuthClient with CredentialStore, HTTPClient wrapper with automatic token refresh on 401
- **CSRF Protection**: Double-submit cookie middleware (`CSRFMiddleware`) for form endpoints, opt-in per-route
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
├── core/                 # Foundation types: User, Identity, Channel, store interfaces,
│                         #   tokens, credentials, scopes, email, context helpers
├── keys/                 # Key storage: KeyRecord, KeyLookup, KeyStorage, InMemoryKeyStore,
│                         #   EncryptedKeyStorage, KidStore, JWKSHandler, JWKSKeyStore
├── admin/                # Admin auth: AdminAuth, AppRegistrar, MintResourceToken
├── apiauth/              # API auth: APIAuth, APIMiddleware, context helpers
├── localauth/            # Local auth: LocalAuth, signup, helpers (NewCreateUserFunc, etc.)
├── httpauth/             # HTTP middleware: Middleware, CSRFMiddleware, OneAuth session mux
├── stores/
│   ├── fs/               # File-based stores (dev)
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

Each subpackage has a `SUMMARY.md` for quick orientation.

## Quick Start

```go
import (
    "github.com/panyam/oneauth/core"
    "github.com/panyam/oneauth/localauth"
    "github.com/panyam/oneauth/apiauth"
    "github.com/panyam/oneauth/stores/fs"
)

// Browser auth
auth := &localauth.LocalAuth{...}
mux.Handle("/auth/login", auth)

// API auth
api := &apiauth.APIAuth{...}
mux.Handle("/api/login", api)

// Protect endpoints with APIMiddleware
middleware := &apiauth.APIMiddleware{
    TokenQueryParam: "token",
}
mux.Handle("/api/protected", middleware.ValidateToken(handler))

// Extract custom claims in handlers
claims := apiauth.GetCustomClaimsFromContext(r.Context())
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

- **v0.0.58**: Token Introspection (#47). `IntrospectionHandler` in `apiauth/` (RFC 7662). Resource servers validate tokens via `POST /oauth/introspect`. Blacklist-aware. 9 unit + 3 e2e tests.
- **v0.0.57**: `client_credentials` grant (#53). Machine-to-machine auth via `APIAuth.ClientKeyStore`. Server + client side. `client_secret_post` and `client_secret_basic`. 8 unit + 2 e2e tests.
- **v0.0.56**: Keycloak interop test suite (#49). 10 tests proving `APIMiddleware` + `JWKSKeyStore` validate Keycloak-issued tokens. Pre-baked realm JSON, `make upkcl/testkcl/downkcl`, manual-trigger CI. Separate Go module.
- **v0.0.55**: Protected Resource Metadata (#46). `ProtectedResourceMetadata` + `NewProtectedResourceHandler` in `apiauth/` (RFC 9728). Resource servers advertise capabilities at `/.well-known/oauth-protected-resource`. 7 unit + 3 e2e tests.
- **v0.0.54**: Fix JWT `aud` array validation (#52). `matchesAudience()` handles both string and array `aud` claims per RFC 7519 §4.1.3. Interop with Keycloak/Auth0/Azure AD. 8 new tests.
- **v0.0.53**: AppRegistrar data race fix (found by e2e race detector). `NewAppRegistrar()` constructor. Python integration tests removed.
- **v0.0.52**: Go e2e tests (#44). 28 in-process tests replacing Python integration suite. Auth + 2 resource servers via httptest.NewServer. All federated tests work (0 skipped). Race-clean. `make e2e`, `make test-hard`.
- **v0.0.50**: Load testing (#38). `hey`-based load tests for health, login, JWT validation, admin endpoints. `make test-hard` now includes unit + integration + load + secrets.
- **v0.0.49**: Secret scanning + ZAP dynamic testing (#36, #37). Gitleaks in CI, ZAP baseline scan on push, all Actions pinned by SHA. `make secrets` for local use.
- **v0.0.48**: JWT token blacklist (#23). `core.TokenBlacklist` interface, `InMemoryBlacklist`, `jti` claim in all access tokens, blacklist check in APIAuth + APIMiddleware. 10 tests.
- **v0.0.47**: PKCE for OAuth2 (#27). Proof Key for Code Exchange (RFC 7636) enabled by default. `DisablePKCE` opt-out. HttpOnly cookie for verifier. 8 tests.
- **v0.0.46**: Integration security tests (#18). 11 full-stack tests, --start-server auto-build, refresh token family revocation bug fix, JWT-protected /api/me endpoint, LimitBody on /apps/.
- **v0.0.45**: Documentation update. All 15 docs synced with subpackage reorg + security hardening.
- **v0.0.44**: Rate limiting, account lockout, timing oracle fix (#31). Login rate limiting via `core.RateLimiter` (token bucket), account lockout via `core.AccountLockout`, CWE-208 timing oracle fix in credential validator.
- **v0.0.43**: Security headers (#28), JWKS ETag (#24), Go 1.26.1 (#14), static analysis (#15), CI pipeline (#35). `SecurityHeaders` middleware, JWKS `ETag`+`304`, `govulncheck` clean, GitHub Actions CI.
- **v0.0.42**: Crypto hardening (#29), body limits (#34), audience fix (#33). Min RSA 2048, no-panic `EncodePrivateKeyPEM`, `SigningMethodForAlg` errors on unknown, `LimitBody` middleware, audience validation in `ValidateAccessToken`.
- **v0.0.41**: Reference links on all security tests. RFC/CVE/CWE/OWASP links in test docstrings.
- **v0.0.40**: Sub-module split (#43), FS path traversal fix (#17). Core module trimmed to 6 deps. Heavy backends are separate Go modules. `safeName()` sanitizer on all FS stores, permissions tightened to 0700/0600. Migration guide: docs/MIGRATION.md.
- **v0.0.39**: Subpackage reorganization + security hardening. Root .go files split into `core/`, `keys/`, `admin/`, `apiauth/`, `localauth/`, `httpauth/`. JWKS `key_ops: ["verify"]` for RFC compliance (#26). JWT security test suite with 13 tests covering algorithm confusion (CVE-2015-9235), claim validation, and edge cases (#16). Closed #4, #7, #16, #21, #26.
- **v0.0.38**: kid in JWTs + KeyStore refactor (#25, #40). All minted JWTs include `kid` header (RFC 7638 thumbprint). Decomposed god KeyStore interface into focused `KeyLookup` (read) and `KeyStorage` (read+write) with `KeyRecord` struct. `EncryptedKeyStorage` correctly computes kid from plaintext. `KidStore` for key rotation grace periods. `CompositeKeyLookup` chains multiple sources. Cross-app forgery prevention via kid owner cross-check. JWKS uses thumbprint kids. All backends updated.
- **v0.0.37**: CSRF protection (#21). `CSRFMiddleware` with double-submit cookie pattern, constant-time comparison, Bearer exemption. Reference server form endpoints protected. 12 unit tests.
- **v0.0.36**: HS256 secret encryption at rest (#19). `EncryptedKeyStore` decorator with AES-256-GCM, HKDF-SHA256 key derivation, plaintext migration fallback. Configured via `ONEAUTH_MASTER_KEY` env var.
- **v0.0.35**: JWKS endpoint for federated public key discovery (#7). `JWKSHandler` serves `/.well-known/jwks.json`, `JWKSKeyStore` fetches keys from remote JWKS URL, `utils/jwk.go` JWK conversion utilities. Demo resource server supports `JWKS_URL` as alternative to shared database.
- **v0.0.34**: Asymmetric JWT signing (RS256/ES256). `MintResourceTokenWithKey`, `APIAuth.JWTSigningKey`/`JWTVerifyKey`, `AppRegistrar` public key registration, `utils/crypto_helpers.go`, keystoretest asymmetric suite, pre-push hook.
- **v0.0.33**: Federated auth demo with guided UI, devloop live-reload, CORS, credential recovery, per-page template routing. Renamed Host/Relay to App/Resource Server throughout.
- **v0.0.32**: APIMiddleware enhancements (TokenQueryParam, GetCustomClaimsFromContext).
- **v0.0.31**: App Registration API (AdminAuth, AppRegistrar, MintResourceToken). Config-driven reference server (`cmd/oneauth-server/`).
- **v0.0.30**: WritableKeyStore interface. Persistent KeyStore backends (GORM, FS, GAE). Shared test suite in `keystoretest/`.
- **v0.0.29**: CustomClaimsFunc, KeyStore interface, InMemoryKeyStore, multi-tenant JWT validation with algorithm confusion prevention.
- **v0.0.28**: Optimistic locking (Version, UpdatedAt) on Identity/Channel. ExpiresAt on Channel for OAuth token expiry tracking.
