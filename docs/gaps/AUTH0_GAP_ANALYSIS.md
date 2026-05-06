# Auth0 vs OneAuth — Gap Analysis

**Original:** 2026-03-17
**Updated:** 2026-05-06
**Purpose:** Comprehensive comparison of Auth0's feature set against OneAuth to identify gaps, strengths, and roadmap priorities.

---

## Executive Summary

Auth0 is a mature, enterprise-grade identity platform with 100+ features spanning authentication, authorization, user management, security, extensibility, and compliance. OneAuth is a focused Go authentication library that has grown from ~30% coverage (March 2026) to **~55% coverage** (May 2026) after adding RFC 9396 RAR, token revocation, transport-independent core, interactive examples, and Keycloak/RAR interop tests.

**Key remaining gaps:** MFA, OIDC provider (ID tokens), authorization code grant as AS, brute force protection, RBAC, user management API, frontend SDKs.

**Key OneAuth advantages over Auth0:** RFC 9396 RAR on standard OAuth flows (Auth0 doesn't have this), embeddable Go library (no SaaS dependency), transport-independent core (works in gRPC/MCP, not just HTTP), federated resource token pattern, no per-user pricing.

---

## What's been CLOSED since the original analysis (March → May 2026)

| Gap | Status | What was done |
|-----|--------|---------------|
| Authorization Code + PKCE | **DONE** | `client/` module with `LoginWithBrowser`, PKCE, auth method negotiation |
| Client Credentials Flow | **DONE** | `APIAuth.ClientKeyStore` enables grant_type=client_credentials |
| OIDC Discovery | **DONE** | `ASServerMetadata` + `NewASMetadataHandler` at `/.well-known/openid-configuration` |
| Token Introspection (RFC 7662) | **DONE** | `IntrospectionHandler` + `IntrospectionValidator` (client-side with caching) |
| Token Revocation (RFC 7009) | **DONE** | `RevocationHandler` at `POST /oauth/revoke` (issue 100, PR 109) |
| DCR (RFC 7591) | **DONE** | `DCRHandler` at `POST /apps/dcr` |
| Protected Resource Metadata (RFC 9728) | **DONE** | `NewProtectedResourceHandler` |
| **RFC 9396 RAR** | **DONE** | Full implementation — Auth0 doesn't have this on standard OAuth flows |
| Transport-independent core | **DONE** | `OneAuth` struct with `TokenIssuer`, `TokenValidator`, `TokenIntrospector`, `TokenRevoker` interfaces (issue 110) |
| Lifecycle hooks | **DONE** | Grouped hooks: `TokenHooks`, `AuthHooks`, `ClientHooks`, `SecurityHooks` |
| PKCE (server-side enforcement) | **Partial** | E2E stub exists; full AS-side authorization code grant not yet production |

---

## Auth0 New Features (2025-2026) — Not in Original Analysis

Auth0 has shipped several new capabilities since our original analysis:

| Feature | Auth0 Status | OneAuth Status | Issue |
|---------|-------------|---------------|-------|
| **Auth0 for AI Agents** (MCP OAuth, CIMD, token refresh for long-running agents) | GA | Partial — mcpkit integration, CIMD validation, ClientCredentialsSource with auto-refresh. Missing: MRRT, scope step-up during agent execution | issue 131 |
| **Multi-Resource Refresh Tokens (MRRT)** | GA (Aug 2025) | None | issue 148 |
| **DPoP for Enterprise Connections** | Early Access | None | issue 94 |
| **Organization Discovery by Domain** | GA | None (part of multi-org) | issue 128 |
| **OAuth 2.1 alignment** (enforce PKCE, deprecate implicit, tighten defaults) | In progress (Oct 2026 enforcement) | None | issue 149 |
| **Multiple Custom Domains** | GA | N/A (self-hosted) | — |
| **Passkey enrollment on custom domains** | GA | No passkey support | issue 127 |
| **Custom Prompts Dashboard Editor** | GA | Basic templates only | issue 140 |
| **Akamai Bot Detection integration** | GA | No bot detection | issue 136 |
| **Self-Service Enterprise SSO Suite** (domain verification, SCIM, Google Directory Sync) | GA | None | issues 130, 133 |

---

## Comparison Matrix (Updated May 2026)

### Legend
- **Full** = Feature parity or equivalent
- **Partial** = Some capability exists but incomplete
- **None** = Not implemented
- **NEW** = Closed since original analysis
- **N/A** = Not applicable (managed service feature)

---

## 1. Authentication API

| Feature | Auth0 | OneAuth | Gap | Issue |
|---------|-------|---------|-----|-------|
| Username/Password Login | POST /oauth/token (ROPC) | POST /api/token (password) | Full | — |
| Signup | POST /dbconnections/signup | POST /auth/signup | Full | — |
| Email Verification | POST /jobs/verification-email | GET /auth/verify-email | Full | — |
| Password Reset | Hosted page + token | POST /auth/forgot-password + reset | Full | — |
| Credential Linking | POST /api/v2/users/{id}/identities | POST /auth/link-credentials | Full | — |
| **Authorization Code + PKCE** | Full | **NEW** — client-side via `AuthClient.LoginWithBrowser` | Full (client) | — |
| **Client Credentials Flow** | Full | **NEW** — `APIAuth.ClientKeyStore` | Full | — |
| Device Authorization Flow | POST /oauth/device/code | None | **None** | issue 117 |
| Passwordless (Email) | POST /passwordless/start | None | **None** | issue 126 |
| Passwordless (SMS) | POST /passwordless/start | None | **None** | issue 126 |
| Passkeys / WebAuthn | Native passkey mgmt | None | **None** | issue 127 |
| Social Login (Google) | Via connections | oauth2/google.go | Full | — |
| Social Login (GitHub) | Via connections | oauth2/github.go | Full | — |
| Social Login (Apple/MS/FB/LinkedIn/X) | Via connections | None | **None** | issue 132 |
| Enterprise SSO (SAML) | Via connections | saml/saml.go | Full | — |
| Enterprise SSO (generic OIDC) | Via connections | None | **None** | issue 133 |
| Enterprise SSO (LDAP/AD) | Via AD Connector | None | **None** | issue 135 |
| Enterprise SSO (WS-Federation) | Via connections | None | **None** | issue 134 |
| SCIM Provisioning | Built-in | None | **None** | issue 130 |
| Refresh Token Rotation | Automatic + theft detection | Family-based rotation + theft detection | Full | — |
| **Token Revocation** | POST /oauth/revoke | **NEW** — `RevocationHandler` (RFC 7009) | Full | — |
| Logout (local) | GET /v2/logout | POST /api/logout + /api/logout-all | Full | — |
| Logout (federated) | GET /v2/logout?federated | None | **None** | issue 129 |
| DPoP | Supported (2025) | None | **None** | issue 94 |

## 2. Token & JWT Management

| Feature | Auth0 | OneAuth | Gap | Issue |
|---------|-------|---------|-----|-------|
| Access Tokens (JWT) | RS256 default | HS256, RS256, ES256 | Full | — |
| ID Tokens (OIDC) | Standard id_token | None | **None** | issue 115 |
| Refresh Tokens | Configurable rotation | Family-based, 7-day default | Full | — |
| API Keys | Via Management API | oa_ prefix, bcrypt hash, scopes | Full | — |
| Custom Claims | Actions/Rules pipeline | CustomClaimsFunc callback | Full | — |
| **Token Introspection (RFC 7662)** | Not standard | **NEW** — Full (`IntrospectionHandler` + caching client) | Full | — |
| Token Exchange (RFC 8693) | Supported | None | **None** | issue 116 |
| **Rich Authorization Requests (RFC 9396)** | None on standard flows | **NEW** — Full (token endpoint, introspection, middleware, discovery) | **OneAuth ahead** | — |
| Multi-tenant Key Management | Per-tenant keys | Per-client KeyStore | Full | — |
| JWKS Endpoint | /.well-known/jwks.json | JWKSHandler + JWKSKeyStore | Full | — |
| **OIDC Discovery** | /.well-known/openid-configuration | **NEW** — `ASServerMetadata` + handler | Full | — |
| MRRT (Multi-Resource Refresh Tokens) | GA (2025) | None | **None** | issue 148 |

## 3. User Management

| Feature | Auth0 | OneAuth | Gap | Issue |
|---------|-------|---------|-----|-------|
| Create User | POST /api/v2/users | NewCreateUserFunc | Full | — |
| Get User by ID | GET /api/v2/users/{id} | UserStore.GetUserById | Full | — |
| Update User | PATCH /api/v2/users/{id} | UserStore.SaveUser | Partial | — |
| Delete User | DELETE /api/v2/users/{id} | None | **None** | issue 123 |
| List/Search Users | GET /api/v2/users (paginated, Lucene) | None | **None** | issue 123 |
| User Blocking | PATCH blocked: true | None | **None** | issue 123 |
| User Roles | GET/POST /api/v2/users/{id}/roles | None | **None** | issue 124 |
| User Permissions | GET /api/v2/users/{id}/permissions | Scopes only | **None** | issue 124 |
| Username Management | Built into user model | UsernameStore (reserve/change/release) | Full | — |
| User Identities | Multiple linked identities | IdentityStore (email/phone) | Full | — |
| Channels / Providers | Connections per identity | ChannelStore (local/oauth/saml) | Full | — |

## 4. Authorization & RBAC

| Feature | Auth0 | OneAuth | Gap | Issue |
|---------|-------|---------|-----|-------|
| Roles | Full RBAC | None | **None** | issue 124 |
| Permissions | Fine-grained per-API | Scopes only | **None** | issue 124 |
| Organizations | Multi-org, per-org roles | None | **None** | issue 128 |
| Scopes | OAuth2 standard | Custom scope system | Partial | — |
| **Scope Enforcement** | Via API settings | `RequireScopes` + **NEW** `RequireAuthorizationDetails` middleware | Full | — |
| Resource Server Registration | POST /api/v2/resource-servers | POST /apps/register + /apps/dcr | Full | — |

## 5. Security Features

| Feature | Auth0 | OneAuth | Gap | Issue |
|---------|-------|---------|-----|-------|
| MFA - TOTP | Built-in | None | **None** | issue 120 |
| MFA - SMS/Push/Email OTP/WebAuthn | Built-in | None | **None** | issue 120 |
| Brute Force Protection | Auto-block after N failures | AccountLockout struct (not wired) | **None** | issue 121 |
| Rate Limiting | Built-in, per-endpoint | Interface only, no built-in impl | **None** | issue 121 |
| Bot Detection | CAPTCHA on suspicious logins | None | **None** | issue 136 |
| Breached Password Detection | External DB | None | **None** | issue 137 |
| Password Complexity | Configurable (length, chars, history) | MinPasswordLength only | **None** | issue 122 |
| Anomaly Detection | Multi-signal + alerts | None | **None** | issue 138 |
| IP Allowlisting | Per-feature allowlists | None | **None** | issue 139 |
| Password Bcrypt Hashing | bcrypt | bcrypt | Full | — |
| Constant-time Comparison | Standard practice | crypto/subtle for API keys | Full | — |
| CSRF Protection | Built-in state | CSRFMiddleware | Full | — |
| Refresh Token Theft Detection | Family revocation | Family-based rotation + revocation | Full | — |
| Algorithm Confusion Prevention | N/A (managed) | Per-client GetExpectedAlg | Full | — |
| **Lifecycle Security Hooks** | N/A | **NEW** — `SecurityHooks.OnBlacklistHit`, `OnAlgorithmMismatch`, `OnTokenRejected` | **OneAuth unique** | — |

## 6. UX Components & SDKs

| Feature | Auth0 | OneAuth | Gap | Issue |
|---------|-------|---------|-----|-------|
| Universal Login | Full-featured, customizable | Basic HTML templates | **None** | issue 140 |
| React/Angular/Vue/Next.js SDKs | Full | None | **None** | issue 141 |
| iOS/Android/Flutter SDKs | Full | None | **None** | issue 142 |
| Go SDK (server) | go-auth0 (Management API) | Full library (this IS the SDK) | Full | — |
| **Client SDK (Go)** | N/A | AuthClient with auto-refresh, discovery, scope step-up | Full | — |
| **gRPC Interceptors** | N/A | Unary + Stream interceptors | **OneAuth unique** | — |
| HTTP Middleware | N/A | ValidateToken, RequireScopes, RequireAuthorizationDetails | Full | — |
| Email Templates | Customizable HTML | ConsoleEmailSender (logging only) | **None** | issue 125 |
| CLI Tool | auth0 CLI | None | **None** | issue 143 |
| **Interactive Examples** | API docs | **NEW** — 10 progressive examples with demokit framework, mermaid diagrams | **OneAuth unique** | — |

## 7. Extensibility & Integrations

| Feature | Auth0 | OneAuth | Gap | Issue |
|---------|-------|---------|-----|-------|
| Actions (post-login, etc.) | 18+ triggers, Node.js | None | **None** | — |
| Webhooks | Via Actions + Log Streaming | None | **None** | issue 147 |
| Log Streaming | Datadog, Splunk, AWS | None | **None** | issue 145 |
| Custom Social Connections | OAuth2 generic | BaseOAuth2 (extensible) | Full | — |
| Custom DB Connections | SQL/REST migration scripts | Three-backend store pattern | Full | — |
| Custom Claims Pipeline | Via Actions | CustomClaimsFunc callback | Full | — |
| Email Providers | SendGrid, Mailgun, SES | Pluggable EmailSender interface | Partial | issue 125 |
| **Lifecycle Hooks** | N/A | **NEW** — `TokenHooks`, `AuthHooks`, `ClientHooks`, `SecurityHooks` | **OneAuth unique** | — |
| Config-driven Server | Dashboard (no config files) | YAML + ${ENV_VAR} substitution | Full | — |

## 8. Management & Operations

| Feature | Auth0 | OneAuth | Gap | Issue |
|---------|-------|---------|-----|-------|
| Admin Dashboard | Full web UI | None | **None** | issue 144 |
| Audit Logs | Searchable event log | None | **None** | issue 32 |
| Log Streaming | Datadog, New Relic | None | **None** | issue 145 |
| Metrics / Analytics | Built-in | None | **None** | issue 146 |
| CLI Tool | auth0 CLI | None | **None** | issue 143 |
| Health Endpoint | Managed (SLA) | /_ah/health | Full | — |
| **Memory Mode** | N/A | **NEW** — `oneauth-server --config memory.yaml` for dev/test | **OneAuth unique** | — |

## 9. Standards Compliance

| Standard | Auth0 | OneAuth | Gap | Issue |
|----------|-------|---------|-----|-------|
| **OAuth 2.0 (RFC 6749)** | Full | **Improved** — password, refresh, client_credentials, auth code (client-side) | Partial (no AS-side auth code) | — |
| **OpenID Connect (OIDC)** | Full | None (discovery only) | **None** | issue 115 |
| SAML 2.0 | Full (IdP + SP) | SP only | Partial | — |
| WS-Federation | Supported | None | **None** | issue 134 |
| SCIM 2.0 | Supported | None | **None** | issue 130 |
| **JWKS (RFC 7517)** | Full | Full | Full | — |
| **Token Revocation (RFC 7009)** | Full | **NEW** — Full | Full | — |
| **Token Introspection (RFC 7662)** | N/A | **NEW** — Full | Full | — |
| **AS Metadata (RFC 8414)** | Full | **NEW** — Full | Full | — |
| **DCR (RFC 7591)** | Full | **NEW** — Full | Full | — |
| **RFC 9396 RAR** | None on standard flows | **NEW** — Full | **OneAuth ahead** | — |
| **RFC 9728 PRM** | N/A | **NEW** — Full | Full | — |
| DPoP (RFC 9449) | Supported | None | **None** | issue 94 |
| PKCE (RFC 7636) | Full | Client-side only | Partial | — |
| PAR (RFC 9126) | Supported | None | **None** | issue 97 |
| mTLS (RFC 8705) | Supported | None | **None** | issue 101 |
| FAPI 2.0 | Supported | None | **None** | issue 98 |
| CIBA | Supported | None | **None** | issue 99 |
| OAuth 2.1 | In progress | None | **None** | issue 149 |
| JWT (RFC 7519) | Full | Full (HS256, RS256, ES256) | Full | — |
| FIDO2/WebAuthn | Supported | None | **None** | issue 127 |

---

## OneAuth Competitive Advantages (vs Auth0)

1. **RFC 9396 RAR on standard OAuth flows** — Auth0 doesn't have this. OneAuth can express "transfer 45 EUR to Merchant A" in token requests. Banking differentiator.

2. **Self-hosted / No vendor lock-in** — Full control over data, deployment. No per-user pricing ($35/mo for 500 MAU on Auth0).

3. **Go-native embeddable library** — Import as a package, not a SaaS dependency. Type-safe callbacks vs Auth0's JS Actions runtime.

4. **Transport-independent core** — `OneAuth` struct works in HTTP, gRPC, MCP, CLI — not just HTTP handlers. Auth0 is HTTP-only.

5. **Federated Resource Token model** — `MintResourceToken` / per-app KeyStore for multi-service architectures. No Auth0 equivalent.

6. **Lifecycle hooks** — `TokenHooks`, `AuthHooks`, `ClientHooks`, `SecurityHooks` for in-process callbacks. More flexible than Auth0's webhook-only model.

7. **gRPC support** — First-class interceptors. Auth0 has no native gRPC support.

8. **Interactive examples** — 10 progressive step-through examples with mermaid diagrams, generated READMEs, RFC references. Auth0 has API docs; OneAuth teaches concepts.

9. **Algorithm confusion prevention** — Explicit per-client algorithm enforcement exposed to the developer. Auth0 handles internally.

10. **Three storage backends** — FS (dev), GORM (SQL), GAE (serverless) with shared test suites. Auth0 is opaque.

11. **Memory mode** — `oneauth-server --config memory.yaml` for instant dev/test. Auth0 requires tenant setup.

---

## Updated Summary Statistics

| Category | Auth0 Features | OneAuth Features | Coverage (Mar 2026) | Coverage (May 2026) |
|----------|---------------|-----------------|---------------------|---------------------|
| Authentication Methods | ~15 | 4 → 6 | ~27% | ~40% |
| OAuth2 Grant Types | 6 | 2 → 4 (password, refresh, client_credentials, auth code client-side) | 33% | 67% |
| User Management | ~15 | 6 | 40% | 40% |
| Security Features | ~12 | 3 → 5 (+ revocation, hooks, algorithm guard) | 25% | 42% |
| UX Components | ~12 SDKs + Universal Login | 1 SDK + templates + 10 examples | ~8% | ~15% |
| Token Types | 4 | 3 | 75% | 75% |
| Standards | 10+ | 4 → 11 (JWT, JWKS, OAuth2, SAML, introspection, revocation, discovery, DCR, PRM, RAR, RFC 9728) | ~33% | ~73% |
| Extensibility | Actions, Rules, Hooks, Webhooks | Callbacks + hooks + config-driven | ~15% | ~25% |
| **Overall Estimated Coverage** | | | **~30%** | **~55%** |

---

## All Open Gap Issues

### P0 — Critical
| Issue | Gap |
|-------|-----|
| issue 88 | Security & RFC compliance audit |
| issue 120 | MFA / TOTP |

### P1 — Important
| Issue | Gap |
|-------|-----|
| issue 108 | Registration approval workflows |
| issue 118 | Redis distributed stores |
| issue 121 | Brute force protection + rate limiting |
| issue 122 | Password complexity policies |
| issue 123 | User management API |
| issue 124 | RBAC (roles + permissions) |
| issue 125 | Email delivery |
| issue 131 | Auth0 AI Agents parity (MCP) |
| issue 132 | Social login (Apple, MS, FB, LinkedIn, X) |
| issue 133 | Generic OIDC IdP |
| issue 32 | Audit logging |

### P2 — Nice to have
| Issue | Gap |
|-------|-----|
| issue 94 | DPoP (RFC 9449) |
| issue 97 | PAR (RFC 9126) |
| issue 101 | mTLS (RFC 8705) |
| issue 115 | Full OIDC (ID tokens, userinfo) |
| issue 116 | Token Exchange (RFC 8693) |
| issue 117 | Device Authorization (RFC 8628) |
| issue 119 | Identity brokering improvements |
| issue 126 | Passwordless (magic link, OTP) |
| issue 127 | Passkeys / WebAuthn |
| issue 128 | Organizations / multi-org |
| issue 129 | Federated logout |
| issue 136 | Bot detection / CAPTCHA |
| issue 137 | Breached password detection |
| issue 138 | Anomaly detection + alerts |
| issue 139 | IP allowlisting |
| issue 140 | Universal Login (customizable pages) |
| issue 141 | Frontend SDKs |
| issue 142 | Mobile SDKs |
| issue 143 | CLI management tool |
| issue 144 | Admin dashboard |
| issue 145 | Log streaming |
| issue 146 | Metrics and analytics |
| issue 147 | Webhooks / event system |
| issue 148 | MRRT |
| issue 149 | OAuth 2.1 alignment |

### P3 — Enterprise / specialized
| Issue | Gap |
|-------|-----|
| issue 98 | FAPI 2.0 certification |
| issue 99 | CIBA |
| issue 130 | SCIM 2.0 |
| issue 134 | WS-Federation |
| issue 135 | LDAP/AD |

---

*Sources: [Auth0 API Documentation](https://auth0.com/docs/api), [Auth0 Changelog](https://auth0.com/changelog), [Auth0 for AI Agents](https://auth0.com/ai), [Auth0 MCP blog](https://auth0.com/blog/mcp-and-auth0-an-agentic-match-made-in-heaven/)*
