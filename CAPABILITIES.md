# OneAuth

## Version
v0.1.35

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
- jwt-bearer-client-auth: RFC 7521 §4.2 + RFC 7523 §2.2 + OIDC Core §9 token-endpoint client authentication via signed JWT (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`). Covers both **`private_key_jwt`** (asymmetric — RS256/ES256/PS256) and **`client_secret_jwt`** (symmetric — HS256/HS384/HS512); the wire protocol is identical, and the path is picked from the client's registered key algorithm. Server-side `ClientAuthenticator` validates iss == sub == client_id, audience, lifetime ≤ 5min, replay-protection via pluggable `JTIStore`, alg-confusion lock against the alg registered for the client (no HS-to-RS or RS-to-HS crossover). Token + introspection + revocation handlers all accept the assertion via a shared `extractClientCredentials` helper. Client SDK ships `MintClientAssertion`, `ClientCredentialsTokenWithAssertion`, and `BrowserLoginConfig.ClientAssertion`. AS metadata advertises both methods in `token_endpoint_auth_methods_supported` plus the matching alg list in `token_endpoint_auth_signing_alg_values_supported`. Closes issues 158 (asymmetric) and 159 (symmetric).
- token-introspection: RFC 7662 endpoint for centralized token validation
- as-discovery-server: RFC 8414 / OIDC Discovery metadata endpoint
- as-discovery-client: Client-side AS metadata discovery with fallback chain. `client.ASMetadata.AuthorizationResponseIssParameterSupported` surfaces the RFC 9207 advertisement (pointer-typed for absent / explicit-false / explicit-true tristate, issue 239). `client/as_metadata_interop_test.go` pins the apiauth↔client wire contract.
- rfc-9207-iss-enforcement: Mix-up-attack defence end-to-end. `BrowserLoginRequest.OnCallback` surfaces the RFC 9207 `iss` query parameter via `CallbackParams.Iss` (issue 235). `client.ValidateIss(iss, expectedIssuer, asAdvertisedSupport, strict)` implements the §2.4 truth table with `errors.Is`-safe `ErrIssMismatch` / `ErrIssMissing` sentinels (issue 238). Comparison is **byte-equal** per RFC 9068 §2.1.1 inheritance — no URL normalization (issue 246, MCP `auth/iss-normalized` conformance). Strict-mode flag enforces iss regardless of AS advertisement for FAPI 2.0 / Open Banking / mixed-IdP environments.
- protected-resource-metadata: RFC 9728 resource server capability advertisement
- browser-login: OAuth authorization code + PKCE for CLI/headless clients (RFC 8252)
- dynamic-client-registration: RFC 7591 DCR endpoint alongside AppRegistrar
- introspection-client: Remote token validation via RFC 7662 with caching
- token-blacklist: JWT revocation via jti-based blacklist
- encryption-at-rest: AES-256-GCM encryption via EncryptedKeyStorage. Content-driven predicate covers HMAC client secrets (HS256/HS384/HS512) **and** PEM blocks whose header type contains `PRIVATE` (`PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `OPENSSH PRIVATE KEY`) — extended in issue 248 to cover private keys persisted under non-JWT Algorithm strings (e.g., `ssh-ed25519` from the `sshkeys/` submodule). Public PEMs stay plaintext for JWKS exposure. Read-path PEM detection uses the `-----BEGIN` prefix as a safe-from-collision marker: AES-GCM's random-nonce prefix can never start that way.
- sshkeys-ed25519: `sshkeys.GenerateEd25519()` returns an OpenSSH-format private PEM + an `authorized_keys`-format public line. Separate Go submodule (`github.com/panyam/oneauth/sshkeys`) mirroring the `stores/{fs,gorm,gae}` shape; depends on `oneauth/keys` + `golang.org/x/crypto/ssh`. Private PEM persists through `EncryptedKeyStorage` automatically — the header type triggers the widened encryption predicate with no caller-side opt-in.
- security-headers: HSTS, CSP, X-Frame-Options middleware
- rich-authorization-requests: RFC 9396 authorization_details on token endpoint, introspection, middleware enforcement
- token-revocation: RFC 7009 endpoint for access and refresh token revocation
- transport-agnostic-core: Every transport-agnostic interface in the library follows the `(ctx context.Context, *XRequest) → (*XResponse, error)` convention. `apiauth/` (issue 175): `TokenIssuer` / `TokenValidator` / `TokenIntrospector` / `TokenRevoker` / `ClientAuthenticator`. `admin/` (issues 168/169/170/172): `ClientRegistrationManager` (RFC 7592 self-service) and `ClientRegistrar` (admin CRUD). HTTP handlers across both packages are thin wrappers; wire formats unchanged. Map to gRPC stubs without further refactor.
- lifecycle-hooks: Grouped callbacks (TokenHooks, AuthHooks, ClientHooks, SecurityHooks) for audit, alerting, integration
- interactive-examples: 10 progressive examples on demokit v0.0.16 — split into `main.go` (server with `--serve` real-port mode) + `walkthrough.go` (client demo). Slim `README.md` + generated `WALKTHROUGH.md` (mermaid + steps + copy-paste curl reproductions). Default `make demo` uses the TUI renderer.
- client-sdk: AuthClient with credential store, auto-refresh, browser login
- oneauth-cli: `cmd/oneauth` Cobra binary covering OAuth 2.0 token acquisition (browser / client-credentials / device / password / refresh), RFC 7662 introspection, RFC 7591/7592 dynamic client registration + management, and RFC 7517 JWKS inspection. `--format json|bash|access-token-only` for shell integration. Dogfoods `client/` SDK + `apiauth.IntrospectionValidator`. `oneauth token device` supports `--open` (browser launch) + `--qr` (ASCII QR code via `mdp/qrterminal/v3`). Issues 255 (token), 258 (introspect / dcr / jwks), 268 (device).
- rfc-8628-device-grant: End-to-end RFC 8628 Device Authorization Grant. AS-side wire protocol: `apiauth.DeviceAuthorizationHandler` serves `POST /device/authorize`; the token endpoint handles `grant_type=urn:ietf:params:oauth:grant-type:device_code` with the §3.5 error taxonomy (`authorization_pending` / `slow_down` / `access_denied` / `expired_token`). User-facing consent UI: `apiauth.DeviceVerificationHandler` serves the four HTML pages (code entry → consent → decision → "return to your device") with built-in overridable templates and narrow function-type CSRF + session integration. `core.DeviceAuthorizationStore` interface with **four backends** — in-memory + FS (#117) + GORM (#269) + GAE Datastore (#270) — share the case- and dash-insensitive `core.UpperUserCode` normalization helper (#281) and the shared `deviceauthtest/` contract suite (#282). AS metadata advertises `device_authorization_endpoint`. **Confidential clients** registered with `token_endpoint_auth_method != "none"` MUST authenticate on the redemption call (via `APIAuth.AppStore` lookup + `ClientAuthenticator` — issue 266). Reference server (`cmd/oneauth-server`) exposes the entire surface via a `device_flow:` yaml block (toggle + expiry/interval + store sub-config) and dogfoods the `apiauth.MountDeviceFlow` helper (#276). End-to-end coverage in `tests/e2e/device_flow_test.go` walks the full arc against an in-process AS. Issues 117, 266, 267, 268, 269, 270, 276, 281, 282.
- device-flow-mount-helper: `apiauth.MountDeviceFlow(mux, cfg)` stamps the five RFC 8628 routes onto an `http.ServeMux` (`POST /device/authorize` + `GET/POST /device` + `GET/POST /device/approve`). Mirrors the `apiauth.MountASMetadata` pattern. `DeviceFlowMountConfig` takes an `*APIAuth` (source of DeviceAuthStore + AppStore + Approve/Deny helpers), `VerificationURI`, `SubjectFromRequest` + `CSRFTokenFromRequest` integration points, and an optional `VerifierMiddleware`. The four browser-facing routes run through the middleware; `/device/authorize` is intentionally unwrapped because it is a machine endpoint and CSRF does not apply. Consumed by both `cmd/oneauth-server` (production, `csrf.Protect` middleware) and `tests/e2e/device_flow_test.go` (shim) so the wire-up is shared, not duplicated. Issue 276.
- device-auth-shared-contract-suite: `deviceauthtest/` package mirrors `appstoretest/` / `keystoretest/` — `RunAll(t, factory)` runs the 10 canonical scenarios (CreateAndGet, NotFound, Collision, ApproveBindsSubjectAndOverridesScopes, ApproveTwice_Rejects, DenyTransitions, UpdatePollingBumpsInterval, DeleteRemovesUserCodeIndex, CleanupExpired, RestartPersists) against every `core.DeviceAuthorizationStore` backend. New `Backend{Store, Reopen}` factory shape lets the suite express RestartPersists uniformly: persistent backends' Reopen constructs a fresh handle bound to the same backing storage; in-memory's Reopen returns the receiver. Adding a fifth backend is a 5-line factory + 1-line `RunAll` invocation. Issue 282.
- oauth-21-alignment: Measured baseline against the [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/). Real gaps closed in the original round: DCR-side redirect URI HTTPS validation (`admin/registrar.go` rejects `http://` redirect URIs except for RFC 8252 §7.3 loopback exemption, accepts RFC 8252 §7.1 native-app private-use schemes), and a deprecation warning on the query-param bearer fallback (OAuth 2.1 §5.4 retired bearer-in-query). The original "remove ROPC" + "remove query-param fallback" follow-ups were rescoped under the capability-gating umbrella #344 — OAuth 2.0 is still the majority deployment shape; the right answer is per-deployment opt-in (nil-handler for grants, flags for policies, per-client DCR `grant_types` enforcement), not removal. Refresh token rotation with reuse detection was already compliant. Full audit table + per-row analysis in [docs/OAUTH21_ALIGNMENT.md](docs/OAUTH21_ALIGNMENT.md). Issue 140 (audit) + #344 (gating framing).
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
