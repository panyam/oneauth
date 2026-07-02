# CLAUDE.md — OneAuth

## What is OneAuth?

Go authentication library with unified local/OAuth auth, multi-tenant JWT, and federated resource server auth. See [README.md](README.md) for full overview.

## Repository Structure

Each subpackage has a `SUMMARY.md` with detailed contents.

| Package | What | Details |
|---------|------|---------|
| `core/` | Foundation types, store interfaces, tokens, scopes, RFC 9396 AuthorizationDetail | [core/SUMMARY.md](core/SUMMARY.md) |
| `keys/` | Key storage, JWKS, EncryptedKeyStorage, KidStore | [keys/SUMMARY.md](keys/SUMMARY.md) |
| `admin/` | AdminAuth, AppRegistrar, DCR (RFC 7591), MintResourceToken | [admin/SUMMARY.md](admin/SUMMARY.md) |
| `apiauth/` | APIAuth, APIMiddleware, OneAuth core, introspection, revocation | [apiauth/SUMMARY.md](apiauth/SUMMARY.md) |
| `localauth/` | Local auth (signup, login, password reset) | [localauth/SUMMARY.md](localauth/SUMMARY.md) |
| `httpauth/` | HTTP middleware, CSRF, session management | [httpauth/SUMMARY.md](httpauth/SUMMARY.md) |
| `client/` | Client SDK (AuthClient, ClientCredentialsSource, discovery) | [client/SUMMARY.md](client/SUMMARY.md) |
| `stores/` | FS, GORM, GAE backend implementations | `stores/*/SUMMARY.md` |
| `sshkeys/` | Ed25519 SSH keypair generator (own go.mod). Returns OpenSSH PEM + `authorized_keys` line; private PEM persists encrypted via `EncryptedKeyStorage` automatically. | [sshkeys/SUMMARY.md](sshkeys/SUMMARY.md) |
| `appstoretest/` / `deviceauthtest/` / `keystoretest/` / `kidstoretest/` | Shared contract test suites — every store backend runs `RunAll(t, factory)` to prove behavioral parity | per-package README |
| `examples/` | 10 progressive interactive examples with demokit | [examples/README.md](examples/README.md) |
| `tests/keycloak/` | Keycloak interop + RAR conformance tests | [tests/keycloak/README.md](tests/keycloak/README.md) |
| `cmd/oneauth-server/` | Config-driven reference server (#194 tracks POC→production-grade ambition) | `cmd/oneauth-server/config.go` |
| `cmd/oneauth/` | Cobra-based client CLI — `oneauth token {browser,client-credentials,password,refresh}` | [cmd/oneauth/SUMMARY.md](cmd/oneauth/SUMMARY.md) |

## Multi-Module Structure

Go workspace with separate sub-modules for heavy backends. See `go.work` for the full list. Sub-modules have `replace` directives for local dev. See [docs/MIGRATION.md](docs/MIGRATION.md) for consumer guide.

## Build & Test

```bash
make test          # Unit tests
make e2e           # E2E tests (in-process)
make testkcl       # Keycloak + RAR issuer interop (auto-starts Docker)
make testall       # Everything (9 stages + report)
make tag V=v0.0.X  # Tag all modules
make pushtag V=v0.0.X  # Push all tags
```

Full command reference: see `Makefile` header comments and `make help` (if available).

## Key Architecture Decisions

- **Client library, not a proxy** — embeddable. `cmd/oneauth-server/` is a reference deployment, not the product.
- **gRPC-shape convention everywhere** — every transport-agnostic interface follows `MethodName(ctx context.Context, req *XRequest) (*XResponse, error)`. Applies to `apiauth/` (`TokenIssuer` / `Validator` / `Introspector` / `Revoker` / `ClientAuthenticator`) and `admin/` (`ClientRegistrationManager` / `ClientRegistrar`). HTTP handlers are thin wrappers. Issue #110 / #175.
- **Storage-agnostic** — interface-based, three backends (FS, GORM, GAE) for KeyStore + UserStore + AppRegistrationStore.
- **Composed interfaces, no god objects** — each impl takes only the deps it needs.
- **Grouped hooks** — `TokenHooks`, `AuthHooks`, `ClientHooks`, `SecurityHooks`. See `apiauth/hooks.go`.
- **`Mount*` helpers for related route groups** — when a feature mounts more than one route on a mux, ship a `apiauth.MountX(mux, cfg)` helper so production and tests share one wire-up. Precedent: `apiauth.MountASMetadata` (RFC 8414), `apiauth.MountDeviceFlow` (RFC 8628). The helper owns route placement and handler construction; callers supply dependencies + integration points (session lookup, CSRF token source, optional middleware). Browser-form routes get the caller's middleware; machine endpoints don't.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for rationale and [docs/ROADMAP.md](docs/ROADMAP.md) for what's shipped vs in flight.

## Standards Compliance

| Endpoint | Handler | RFC |
|----------|---------|-----|
| `POST /api/token` (password / refresh / client_credentials / jwt-bearer / token-exchange / device_code / authorization_code) | `TokenEndpointHandler.ServeHTTP` (dispatches to `TokenIssuer` + `AuthorizationCodeGranter` + `DeviceCodeGranter` + `JwtBearerGranter` + `TokenExchanger`) | RFC 6749, 7523, 8693 |
| `POST /oauth/introspect` | `IntrospectionHandler` | RFC 7662 |
| `POST /oauth/revoke` | `RevocationHandler` | RFC 7009 |
| `GET /.well-known/openid-configuration` | `NewASMetadataHandler` | RFC 8414 |
| `GET /.well-known/jwks.json` | `JWKSHandler` | RFC 7517 |
| `GET /.well-known/oauth-protected-resource` | `NewProtectedResourceHandler` | RFC 9728 |
| `POST /apps/dcr` | `DCRHandler` | RFC 7591 |
| `GET / PUT / DELETE /apps/dcr/{client_id}` | `DCRManagementHandler` | RFC 7592 |
| AS-initiated `POST <backchannel_logout_uri>` with `logout_token` | `BCLDispatcher` + `LogoutTokenIssuer` | OIDC Back-Channel Logout 1.0 |
| `POST /device/authorize` + `POST /api/token` (`grant_type=…:device_code`) | `DeviceAuthorizationHandler` + `DeviceCodeGranter` | RFC 8628 |
| `GET / POST /authorize` + `POST /api/token` (`grant_type=authorization_code`) | `AuthorizationHandler` + `AuthorizeVerificationHandler` + `AuthorizationCodeGranter` (via `MountAuthorize`) | RFC 6749 §4.1 + RFC 7636 (PKCE S256) + RFC 9207 (`iss` on redirect) |
| Authorize-redirect `?iss=` query param | (issuer URL on redirects) | RFC 9207 |
| `traceparent` / `tracestate` inbound + outbound (SEP-414 / #254) | `tracing/` + per-handler `TracerProvider` | [W3C Trace Context](https://www.w3.org/TR/trace-context/) |
| `POST /api/token` (`requested_token_type=...:id-jag` issuance / ID-JAG redemption for MCP EMA) | `TokenExchanger` + `IDJAGIssuer` (`apiauth/id_jag.go`) → `JwtBearerGranter` | draft-ietf-oauth-identity-assertion-authz-grant-04 + MCP EMA / SEP-990 |

ID-JAG issuance is opt-in (`OneAuthConfig.IDJAGIssuer`); redemption rides the jwt-bearer grant with single-use `jti` + `client_id` binding. See [docs/oauth/RFC_8693.md](docs/oauth/RFC_8693.md) and [docs/oauth/RFC_7523.md](docs/oauth/RFC_7523.md).

RFC 9396 (Rich Authorization Requests) supported on token endpoint, introspection, and middleware. See `core/authorization_details.go`. Full Authlete-superset gap analysis: [docs/gaps/AUTHLETE_GAP_ANALYSIS.md](docs/gaps/AUTHLETE_GAP_ANALYSIS.md), tracked under #163.

## Conventions

- Each subpackage has a `SUMMARY.md` for LLM discoverability.
- **Documented-contract bar for store backends.** Every exported method on a `stores/*` (or sibling-submodule) store carries a doc comment capturing the WHY of the contract: error-sentinel mapping (`datastore.ErrNoSuchEntity` → `core.ErrAppNotFound` etc.), idempotency promises, transactional scope, non-obvious dances (Get-then-Delete, family-revoke-outside-transaction). Precedents: `stores/gae/appstore.go` (PR 234), `stores/gae/keystore.go`/`kidstore.go`/`stores.go`/`models.go` (#236 / #288). Match the polished precedent, not the closest one — sparse local style isn't license to ship undocumented public API.
- Security tests must include `// See:` links to RFC/CVE/CWE references.
- Use `GH_TOKEN="$GH_PERSONAL_TOKEN"` for gh CLI.
- Keep new test groups in separate `_test.go` files (don't bloat existing ones).
- Sub-modules need `GOWORK=off` when running outside workspace.
- Examples split into `main.go` (server, `--serve` for real ports) + `walkthrough.go` (demokit client demo). Slim `README.md` + generated `WALKTHROUGH.md` via `make walkthrough`.

## Gotchas

- **Keycloak port collision**: Default `KC_PORT=8180`, default `RAR_PORT=8181`. `mcpkit-keycloak` (other project) often holds 8180; pass `make upkcl KC_PORT=8281 && make testkcl KC_PORT=8281` to avoid both that and the RAR_PORT clash.
- **RAR test issuer**: lives at `cmd/oneauth-server/deploy-examples/rar-test.yaml`, started inside `make testkcl`. Old `cmd/rar-test-issuer/` is retired.
- **JWKS only exposes asymmetric keys.** HS256 secrets are *correctly* omitted (`keys/jwks_handler.go`). Tests/services that validate via `JWKSKeyStore` must mint RS256/ES256 tokens — set `jwt.signing_alg: RS256` + `jwt.private_key_path` (or `ephemeral_signing_key: true` for tests).
- **Asymmetric signing in cmd/oneauth-server**: `jwt.signing_alg=RS256` requires either `jwt.private_key_path` or `jwt.ephemeral_signing_key: true` — neither set fails loudly. Auto-generated ephemeral keys invalidate tokens on restart.
- **Local main can be locked by another worktree**. When working in a stacked branch, cut new branches from `origin/main` directly (`git checkout -b feat/X origin/main`) — don't try to `git checkout main` if the `conformance/` or `rfc-extensions/` worktrees own it.
- **`go.work` Go directive**: stdlib CVEs require keeping the `go` directive across all 9 modules in lock-step (root + workspace + 7 sub-modules). `make vulncheck` is the gate.
- **Backlinks via `#N`**: only when the cross-reference is genuinely the audit trail you want. For background-only references, use plain text (`"issue 123"` not `#123`) — see global `~/.claude/CLAUDE.md` for the full rule.
- **httptest URL needed before mount.** When a handler config requires the server's base URL (e.g., RFC 8628 `VerificationURI`), use `httptest.NewUnstartedServer(mux)` → read `server.URL` → mount → `server.Start()`. Avoids post-hoc handler mutation. Pattern in `tests/e2e/device_flow_test.go`.

## Gap analyses

- [docs/gaps/AUTH0_GAP_ANALYSIS.md](docs/gaps/AUTH0_GAP_ANALYSIS.md) — vs Auth0 (full IdP-as-a-service)
- [docs/gaps/AUTHLETE_GAP_ANALYSIS.md](docs/gaps/AUTHLETE_GAP_ANALYSIS.md) — vs Authlete (semi-hosted OAuth backend); meta-tracker issue #163

## Federated Auth Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) or the [examples/README.md](examples/README.md) Cast of Characters for the full picture. Three projects collaborate: oneauth (auth library), massrelay (WebSocket relay), excaliframe (document app).

## Memories

Design lessons from past sessions in `memories/`. See `memories/MEMORY.md` for index. Always save memories to `memories/` (not `~/.claude/`).
