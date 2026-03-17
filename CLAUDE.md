# CLAUDE.md — OneAuth

## What is OneAuth?

Go authentication library with unified local/OAuth auth, multi-tenant JWT (KeyStore with HS256/RS256/ES256), and an App Registration API for federated resource server auth. Three storage backends: filesystem, GORM (SQL), and GAE/Datastore.

## Repository Structure

```
oneauth/
├── *.go                  # Core types: User, Identity, Channel, LocalAuth, APIAuth,
│                         #   APIMiddleware, KeyStore, WritableKeyStore, AdminAuth,
│                         #   AppRegistrar, MintResourceToken, MintResourceTokenWithKey
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

## Build & Test Commands

```bash
make test          # Go unit tests (all packages)
make testpg        # GORM tests against PostgreSQL (auto-starts Docker)
make testds        # GAE tests against Datastore emulator (auto-starts Docker)
make testrealDS    # GAE tests against real Datastore (needs credentials)
make integ         # Integration tests against live GAE (pytest, uv+venv)
make deploygae     # Deploy to GAE (project: oneauthsvc)
make gaelogs       # Tail GAE logs
```

## Key Patterns

### Shared Test Suites (Factory Pattern)
`keystoretest.RunAll(t, factory)` runs identical tests against any `WritableKeyStore` implementation. Each backend test file creates a factory that returns its store type. This is the pattern to follow for any new interface with multiple backends.

### Three-Backend Store Pattern
Every persistent interface (UserStore, IdentityStore, ChannelStore, WritableKeyStore) has three implementations: `stores/fs/`, `stores/gorm/`, `stores/gae/`. New store types must implement all three. GORM models use dialect-agnostic column types — never use `type:blob` (fails on PostgreSQL), let GORM auto-select.

### Config-Driven Reference Server
`cmd/oneauth-server/` uses YAML config with `${ENV_VAR:-default}` substitution. On GAE (no config file), falls back to `configFromEnv()` which reads all config from env vars. The server supports memory, fs, gorm (postgres only — sqlite requires CGO), and gae keystores.

### AdminAuth Interface
`AdminAuth.Authenticate(r *http.Request) error` — constant-time API key comparison (`crypto/subtle`). Implementations: `APIKeyAuth` (reads `X-Admin-Key` header), `NoAuth` (dev only). On GAE, the API key is fetched from Secret Manager at startup if `ADMIN_API_KEY` env var is not set.

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

Flow: App registers with oneauth-server → gets `client_id` + `client_secret` (HS256) or registers a public key (RS256/ES256) → App authenticates users locally → mints resource-scoped JWTs with `MintResourceToken()` or `MintResourceTokenWithKey()` → resource server validates using shared KeyStore or JWKS discovery (`/.well-known/jwks.json`).

## Conventions

- Update SUMMARY.md, NEXTSTEPS.md, ROADMAP.md with each PR
- GitHub issues track all planned work with priority levels (P0/P1/P2)
- Use `GH_TOKEN="$GH_PERSONAL_TOKEN"` for gh CLI (Enterprise Managed User)
- PostgreSQL test container: `arm64v8/postgres:18.1` on port 5433
- Datastore test credentials: `~/dev-app-data/secrets/gappeng/gappeng-7bb71377bfa2.json`
