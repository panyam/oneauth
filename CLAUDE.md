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
| `examples/` | 10 progressive interactive examples with demokit | [examples/README.md](examples/README.md) |
| `tests/keycloak/` | Keycloak interop + RAR conformance tests | [tests/keycloak/README.md](tests/keycloak/README.md) |
| `cmd/oneauth-server/` | Config-driven reference server | `cmd/oneauth-server/config.go` |
| `cmd/rar-test-issuer/` | Minimal RAR-capable AS for interop testing | `cmd/rar-test-issuer/main.go` header |

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

- **Client library, not a proxy** — embeddable, no extra service to operate
- **Transport-independent core** — `OneAuth` struct with `TokenIssuer`, `TokenValidator`, `TokenIntrospector`, `TokenRevoker` interfaces. HTTP handlers are thin wrappers. See [#110](https://github.com/panyam/oneauth/issues/110).
- **Storage-agnostic** — interface-based, three backends (FS, GORM, GAE)
- **Composed interfaces** — no god objects. Each implementation takes only the deps it needs.
- **Grouped hooks** — `TokenHooks`, `AuthHooks`, `ClientHooks`, `SecurityHooks`. See `apiauth/hooks.go`.

## Standards Compliance

| Endpoint | Handler | RFC |
|----------|---------|-----|
| `POST /api/token` | `APIAuth.ServeHTTP` | RFC 6749 |
| `POST /oauth/introspect` | `IntrospectionHandler` | RFC 7662 |
| `POST /oauth/revoke` | `RevocationHandler` | RFC 7009 |
| `GET /.well-known/openid-configuration` | `NewASMetadataHandler` | RFC 8414 |
| `GET /.well-known/jwks.json` | `JWKSHandler` | RFC 7517 |
| `GET /.well-known/oauth-protected-resource` | `NewProtectedResourceHandler` | RFC 9728 |
| `POST /apps/dcr` | `DCRHandler` | RFC 7591 |

RFC 9396 (Rich Authorization Requests) supported on token endpoint, introspection, and middleware. See `core/authorization_details.go`.

## Conventions

- Each subpackage has a `SUMMARY.md` for LLM discoverability
- Security tests must include `// See:` links to RFC/CVE/CWE references
- Use `GH_TOKEN="$GH_PERSONAL_TOKEN"` for gh CLI
- Keycloak: `quay.io/keycloak/keycloak:26.6` on port 8180
- RAR test issuer: port 8181. See `cmd/rar-test-issuer/main.go` for details.
- Sub-modules need `GOWORK=off` when running outside workspace

## Federated Auth Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) or the [examples/README.md](examples/README.md) Cast of Characters for the full picture. Three projects collaborate: oneauth (auth library), massrelay (WebSocket relay), excaliframe (document app).

## Memories

Design lessons from past sessions in `memories/`. See `memories/MEMORY.md` for index. Always save memories to `memories/` (not `~/.claude/`).
