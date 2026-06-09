# OneAuth

## Version
v0.1.20

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
- pluggable-app-registry: AppRegistrationStore interface for persisting registered apps. In-memory (issue 165), filesystem (issue 166), and GORM SQL (issue 167) backends all ship. Reference server (cmd/oneauth-server) exposes the choice via `app_store.type`. Closes parent issue 20.
- asymmetric-issuer-signing: Reference server supports RS256/ES256 token signing (`jwt.signing_alg`). Public half is registered in the keystore so JWKS exposes it for remote resource servers to validate without a shared secret. Production deployments set `jwt.private_key_path`; tests/dev opt into ephemeral keys via explicit `jwt.ephemeral_signing_key: true` so misconfiguration fails loudly. Closes issue 184.
- dcr-management-rfc7592: Full RFC 7592 verb trio at /apps/dcr/{client_id} — GET (issue 168), PUT with registration_access_token rotation (issue 169), DELETE with credential invalidation (issue 170), Keycloak lifecycle interop (issue 171). Clients receive registration_access_token + registration_client_uri at registration time. Backed by a transport-agnostic ClientRegistrationManager interface (admin/client_management.go) following the (ctx, *Req) → (*Resp, error) convention adopted across the library.
- http-middleware: Auth middleware for HTTP handlers with scope enforcement
- user-identity-model: Three-layer User→Identity→Channel model
- client-credentials-grant: Machine-to-machine auth (RFC 6749 §4.4)
- private-key-jwt-client-auth: RFC 7521 §4.2 + RFC 7523 §2.2 + OIDC Core §9 token-endpoint client authentication via signed JWT (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`). Server-side `ClientAuthenticator` validates iss == sub == client_id, audience, lifetime ≤ 5min, replay-protection via pluggable `JTIStore`, alg-confusion lock against the alg registered for the client. Token + introspection + revocation handlers all accept the assertion via a shared `extractClientCredentials` helper. Client SDK ships `MintClientAssertion`, `ClientCredentialsTokenWithAssertion`, and `BrowserLoginConfig.ClientAssertion`. AS metadata advertises `private_key_jwt` in `token_endpoint_auth_methods_supported` and the new `token_endpoint_auth_signing_alg_values_supported`. Closes issue 158.
- token-introspection: RFC 7662 endpoint for centralized token validation
- as-discovery-server: RFC 8414 / OIDC Discovery metadata endpoint
- as-discovery-client: Client-side AS metadata discovery with fallback chain. `client.ASMetadata.AuthorizationResponseIssParameterSupported` surfaces the RFC 9207 advertisement (pointer-typed for absent / explicit-false / explicit-true tristate, issue 239). `client/as_metadata_interop_test.go` pins the apiauth↔client wire contract.
- rfc-9207-iss-enforcement: Mix-up-attack defence end-to-end. `BrowserLoginRequest.OnCallback` surfaces the RFC 9207 `iss` query parameter via `CallbackParams.Iss` (issue 235). `client.ValidateIss(iss, expectedIssuer, asAdvertisedSupport, strict)` implements the §2.4 truth table with `errors.Is`-safe `ErrIssMismatch` / `ErrIssMissing` sentinels (issue 238). Comparison is **byte-equal** per RFC 9068 §2.1.1 inheritance — no URL normalization (issue 246, MCP `auth/iss-normalized` conformance). Strict-mode flag enforces iss regardless of AS advertisement for FAPI 2.0 / Open Banking / mixed-IdP environments.
- protected-resource-metadata: RFC 9728 resource server capability advertisement
- browser-login: OAuth authorization code + PKCE for CLI/headless clients (RFC 8252)
- dynamic-client-registration: RFC 7591 DCR endpoint alongside AppRegistrar
- introspection-client: Remote token validation via RFC 7662 with caching
- token-blacklist: JWT revocation via jti-based blacklist
- encryption-at-rest: AES-256-GCM encryption of HS256 secrets via EncryptedKeyStorage
- security-headers: HSTS, CSP, X-Frame-Options middleware
- rich-authorization-requests: RFC 9396 authorization_details on token endpoint, introspection, middleware enforcement
- token-revocation: RFC 7009 endpoint for access and refresh token revocation
- transport-agnostic-core: Every transport-agnostic interface in the library follows the `(ctx context.Context, *XRequest) → (*XResponse, error)` convention. `apiauth/` (issue 175): `TokenIssuer` / `TokenValidator` / `TokenIntrospector` / `TokenRevoker` / `ClientAuthenticator`. `admin/` (issues 168/169/170/172): `ClientRegistrationManager` (RFC 7592 self-service) and `ClientRegistrar` (admin CRUD). HTTP handlers across both packages are thin wrappers; wire formats unchanged. Map to gRPC stubs without further refactor.
- lifecycle-hooks: Grouped callbacks (TokenHooks, AuthHooks, ClientHooks, SecurityHooks) for audit, alerting, integration
- interactive-examples: 10 progressive examples on demokit v0.0.16 — split into `main.go` (server with `--serve` real-port mode) + `walkthrough.go` (client demo). Slim `README.md` + generated `WALKTHROUGH.md` (mermaid + steps + copy-paste curl reproductions). Default `make demo` uses the TUI renderer.
- client-sdk: AuthClient with credential store, auto-refresh, browser login
- oneauth-cli: `cmd/oneauth` Cobra binary covering OAuth 2.0 token acquisition (browser / client-credentials / device / password / refresh), RFC 7662 introspection, RFC 7591/7592 dynamic client registration + management, and RFC 7517 JWKS inspection. `--format json|bash|access-token-only` for shell integration. Dogfoods `client/` SDK + `apiauth.IntrospectionValidator`. `oneauth token device` supports `--open` (browser launch) + `--qr` (ASCII QR code via `mdp/qrterminal/v3`). Issues 255 (token), 258 (introspect / dcr / jwks), 268 (device).
- rfc-8628-device-grant: AS-side wire protocol for the Device Authorization Grant (RFC 8628). `apiauth.DeviceAuthorizationHandler` serves `POST /device/authorize`; the token endpoint handles `grant_type=urn:ietf:params:oauth:grant-type:device_code` with the §3.5 error taxonomy (`authorization_pending` / `slow_down` / `access_denied` / `expired_token`). `core.DeviceAuthorizationStore` interface with in-memory + FS backends (GORM/GAE deferred). `APIAuth.ApproveDeviceAuthorization` / `DenyDeviceAuthorization` programmatic helpers for the consent UI to wire (UI follow-up filed). AS metadata advertises `device_authorization_endpoint`. **Confidential clients** registered with `token_endpoint_auth_method != "none"` MUST authenticate on the redemption call (via `APIAuth.AppStore` lookup + `ClientAuthenticator` — issue 266). Issues 117, 266.
- test-infrastructure: Reusable testutil package with TestAuthServer (RSA, JWKS, AS metadata) and shared OAuth helpers

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
require github.com/panyam/oneauth v0.1.13

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
    "github.com/panyam/oneauth/testutil" // test infrastructure
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
