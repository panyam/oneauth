# CLAUDE.md — OneAuth

## What is OneAuth?

Go authentication library with unified local/OAuth auth, multi-tenant JWT (KeyStore with HS256/RS256/ES256), and an App Registration API for federated resource server auth. Three storage backends: filesystem, GORM (SQL), and GAE/Datastore.

## Repository Structure

```
oneauth/
├── doc.go                # Package overview (routes to subpackages)
├── core/                 # Foundation types: User, Identity, Channel, store interfaces,
│                         #   tokens, credentials, scopes, email, context helpers
├── keys/                 # Key storage: KeyRecord, KeyLookup, KeyStorage, InMemoryKeyStore,
│                         #   EncryptedKeyStorage, KidStore, JWKSHandler, JWKSKeyStore
├── admin/                # Admin auth: AdminAuth, AppRegistrar, MintResourceToken
├── apiauth/              # API auth: APIAuth, APIMiddleware, context helpers
├── localauth/            # Local auth: LocalAuth, signup, helpers (NewCreateUserFunc, etc.)
├── httpauth/             # HTTP middleware: Middleware, CSRFMiddleware, OneAuth session mux
├── utils/                # Crypto helpers (PEM encode/decode, DecodeVerifyKey, key generation, JWK conversion)
├── stores/
│   ├── fs/               # File-based stores + FSKeyStore
│   ├── gorm/             # GORM SQL stores + GORMKeyStore + SigningKeyModel
│   └── gae/              # Google Datastore stores + GAEKeyStore
├── keystoretest/         # Shared WritableKeyStore test suite (factory pattern)
├── client/               # Client SDK (CredentialStore, AuthClient, HTTPClient)
│   └── stores/fs/        # FS-based credential store
├── grpc/                 # gRPC auth interceptors
├── oauth2/               # OAuth2 provider implementations
├── cmd/oneauth-server/   # Reference server (config-driven, deployable)
│   ├── main.go           # Wiring: KeyStore + AdminAuth + AppRegistrar
│   ├── config.go         # YAML config + ${ENV_VAR:-default} substitution
│   ├── Dockerfile
│   └── deploy-examples/  # GAE, Docker Compose, Kubernetes
├── tests/integration/    # Pytest integration tests (against live server)
└── Makefile
```

### Dependency DAG (strictly acyclic)

```
              core
            / | \  \
           /  |  \  \
        keys  |  localauth
        / \   |
       /   \  |
    admin  apiauth
              |
           httpauth
```

Each subpackage has a `SUMMARY.md` describing its contents.

### Multi-Module Structure

The repo is a Go workspace with multiple modules. The core module is lightweight (~6 deps). Heavy backends are separate sub-modules:

| Module | Heavy Deps |
|--------|-----------|
| `github.com/panyam/oneauth` (core) | None — jwt, scs, x/crypto, x/oauth2 only |
| `stores/gorm` | gorm.io/gorm, postgres/sqlite drivers |
| `stores/gae` | cloud.google.com/go/datastore + GCP SDK |
| `saml` | crewjam/saml |
| `grpc` | google.golang.org/grpc |
| `oauth2` | golang.org/x/oauth2/google |
| `cmd/*` | Various (integration points) |

`go.work` at root enables local multi-module dev. Sub-modules have `replace` directives for `go mod tidy` compatibility. See [docs/MIGRATION.md](docs/MIGRATION.md) for consumer migration guide.

**Publish workflow:** `make norep` → tag all modules → push → `make rep` → `make tidy`

## Build & Test Commands

```bash
# Multi-module (all modules at once)
make ball          # Build all modules (binaries → build/)
make tall          # Test all modules
make tidy          # go mod tidy all modules
make deps          # Show core module dep count

# Testing
make test          # Go unit tests (root module packages)
make e2e           # Go e2e tests (in-process auth + resource servers, race detector)
make test-hard     # Full suite: unit + e2e + secret scan
make testpg        # GORM tests against PostgreSQL (auto-starts Docker)
make testds        # GAE tests against Datastore emulator (auto-starts Docker)
make testrealDS    # GAE tests against real Datastore (needs credentials)
make testkcl       # Keycloak interop tests (auto-starts Docker, ~15s startup)
make upkcl         # Start Keycloak container only
make downkcl       # Stop Keycloak container
make kcllogs       # Tail Keycloak container logs

# Security scanning
make audit         # Full security audit: vulncheck + gosec + secrets + race detection
make vulncheck     # govulncheck on all modules
make seccheck      # gosec security patterns
make lint          # staticcheck code quality
make secrets       # gitleaks secret scanning

# Publishing
make norep         # Remove replace directives (before tagging releases)
make rep           # Restore replace directives (after publishing)

# Infrastructure
make deploygae     # Deploy to GAE (project: oneauthsvc)
make gaelogs       # Tail GAE logs
```

### E2E Tests (`tests/e2e/`)

In-process e2e tests using `httptest.NewServer`. Auth server + 2 resource servers start in ~2s, race detector works across all servers. Remote mode: `TEST_BASE_URL=https://... make e2e` for deployed server testing.

**Always use `NewAppRegistrar()`** constructor (not struct literal) — the map must be initialized to avoid data races under concurrent requests.

## Import Map (Post-Reorganization)

| What | Import |
|---|---|
| User, Identity, Channel, store interfaces, tokens, credentials, scopes | `"github.com/panyam/oneauth/core"` |
| KeyStorage, KeyRecord, InMemoryKeyStore, EncryptedKeyStorage, JWKSHandler | `"github.com/panyam/oneauth/keys"` |
| AdminAuth, AppRegistrar, MintResourceToken, AppQuota | `"github.com/panyam/oneauth/admin"` |
| APIAuth, APIMiddleware, GetUserIDFromAPIContext | `"github.com/panyam/oneauth/apiauth"` |
| LocalAuth, NewCreateUserFunc, NewCredentialsValidator | `"github.com/panyam/oneauth/localauth"` |
| Middleware, CSRFMiddleware, CSRFTemplateField, OneAuth | `"github.com/panyam/oneauth/httpauth"` |

## Key Patterns

### Shared Test Suites (Factory Pattern)
`keystoretest.RunAll(t, factory)` runs identical tests against any `KeyStorage` implementation. Each backend test file creates a factory that returns its store type. This is the pattern to follow for any new interface with multiple backends.

### Three-Backend Store Pattern
Every persistent interface (UserStore, IdentityStore, ChannelStore, KeyStorage) has three implementations: `stores/fs/`, `stores/gorm/`, `stores/gae/`. New store types must implement all three. GORM models use dialect-agnostic column types — never use `type:blob` (fails on PostgreSQL), let GORM auto-select.

Store backends import `core/` for entity types and `keys/` for key types.

### Config-Driven Reference Server
`cmd/oneauth-server/` uses YAML config with `${ENV_VAR:-default}` substitution. On GAE (no config file), falls back to `configFromEnv()` which reads all config from env vars. The server supports memory, fs, gorm (postgres only — sqlite requires CGO), and gae keystores.

### KeyStorage / KeyLookup Interfaces (in keys/)
The key storage layer uses two focused interfaces instead of a single god interface:
- `KeyLookup` (read-only): `GetKey(clientID)` + `GetKeyByKid(kid)` → returns `*KeyRecord`
- `KeyStorage` (read+write): embeds `KeyLookup` + `PutKey`, `DeleteKey`, `ListKeyIDs`
- `KeyRecord` struct: `{ClientID, Key, Algorithm, Kid}` — all fields in one place

All backends (InMemory, GORM, FS, GAE) implement `KeyStorage`. `JWKSKeyStore` and `KidStore` implement only `KeyLookup`.

Backward-compatible alias methods (`RegisterKey`, `GetVerifyKey`, `GetExpectedAlg`, `ListKeys`) exist on all backends for migration. Prefer the new `KeyStorage` methods in new code.

### EncryptedKeyStorage (Decorator Pattern, in keys/)
`EncryptedKeyStorage` wraps any `KeyStorage` to encrypt HS256 secrets at rest using AES-256-GCM. Kid is computed from plaintext before encryption. Configured via `ONEAUTH_MASTER_KEY` env var (64 hex chars = 32 bytes). Plaintext fallback on read enables migration. See [JWT_SIGNING.md](docs/JWT_SIGNING.md#encryption-at-rest-encryptedkeystore) for details.

### kid (Key ID) in JWTs
All minted JWTs include a `kid` header (RFC 7638 thumbprint). `APIMiddleware` tries kid-based lookup first (`GetKeyByKid`), then falls back to `client_id` claim (`GetKey`). Legacy tokens without `kid` still work. Key rotation uses `KidStore` to retain old keys with a grace period expiry.

### AdminAuth Interface (in admin/)
`AdminAuth.Authenticate(r *http.Request) error` — constant-time API key comparison (`crypto/subtle`). Implementations: `APIKeyAuth` (reads `X-Admin-Key` header), `NoAuth` (dev only). On GAE, the API key is fetched from Secret Manager at startup if `ADMIN_API_KEY` env var is not set.

### BasicUser (in core/)
`BasicUser` has exported fields `ID` and `ProfileData` (not the original unexported `id`/`profile`). This was changed during the subpackage reorganization for cross-package access.

### Integration Tests
`tests/integration/` — self-contained pytest files, one per scenario. Uses `conftest.py` with `OneAuthClient` fixture. Run with `make integ` or `make -C tests/integration test-health`. Uses uv+venv for dependency management.

## GAE Deployment Notes

- Runtime: `go124` (not go125 — doesn't exist yet)
- No sqlite in reference server — `mattn/go-sqlite3` requires CGO, unavailable on GAE standard
- Health endpoint: `/_ah/health` (GAE intercepts `/healthz`)
- Deploy from repo root: `gcloud app deploy --appyaml=cmd/oneauth-server/deploy-examples/gae/app.yaml --project=oneauthsvc .`
- Source must be module root (not the app.yaml directory) so `main: ./cmd/oneauth-server` resolves
- GAE project: `oneauthsvc` (us-west1, free tier: F1 instance, scale-to-zero)
- Admin key stored in Secret Manager: `oneauth-admin-key`

## Federated Auth Architecture

Three projects collaborate:
1. **oneauth** (this repo) — shared auth library + App Registration API
2. **massrelay** — WebSocket relay (a resource server), validates resource-scoped JWTs using KeyStore
3. **excaliframe** (document app) — registers as an App, mints resource tokens for users

Flow: App registers with oneauth-server → gets `client_id` + `client_secret` (HS256) or registers a public key (RS256/ES256) → App authenticates users locally → mints resource-scoped JWTs with `admin.MintResourceToken()` or `admin.MintResourceTokenWithKey()` → resource server validates using shared KeyStore or JWKS discovery (`/.well-known/jwks.json`).

## Memories

Design lessons and feedback from past sessions are in `memories/`. See `memories/MEMORY.md` for the index. These are checked into the repo so they're available to all collaborators.

**Important:** Always save memories to the `memories/` folder in this repo (not `~/.claude/`). This keeps them version-controlled and available to all collaborators. Update `memories/MEMORY.md` index when adding new entries.

## Conventions

- Update SUMMARY.md, NEXTSTEPS.md, ROADMAP.md with each PR
- Each subpackage has a SUMMARY.md for LLM discoverability
- GitHub issues track all planned work with priority levels (P0/P1/P2)
- Use `GH_TOKEN="$GH_PERSONAL_TOKEN"` for gh CLI (Enterprise Managed User)
- PostgreSQL test container: `arm64v8/postgres:18.1` on port 5433
- Datastore test credentials: `~/dev-app-data/secrets/gappeng/gappeng-7bb71377bfa2.json`
- **Security tests must include `// See:` links** to the relevant RFC, CVE, CWE, or OWASP reference in each test function's doc comment. This makes it easy to trace why a test exists and what attack it prevents. Example: `// See: https://nvd.nist.gov/vuln/detail/CVE-2015-9235`
