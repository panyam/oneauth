# Demos & Scenarios

Runnable demos that exercise key OneAuth scenarios end-to-end. Each section describes what the demo proves, how it simplifies things for clarity, and what changes in a real deployment.

---

## Demo 1: Federated Resource Server Auth

**Location**: `demo/` (Docker Compose) + `cmd/demo-hostapp/` + `cmd/demo-resource-server/`

### What It Demonstrates

Multiple independent applications ("Apps") register with a central auth server, authenticate their own users independently, mint resource-scoped JWTs, and have those tokens validated by resource servers that share no direct connection to the apps.

This answers the core question: **How does a resource server trust a JWT issued by an application it has never seen before?**

Answer: a shared PostgreSQL `signing_keys` table acts as the trust anchor. OneAuth server writes signing keys at app registration time. Resource servers read from it at validation time.

### Service Topology

```
PostgreSQL (shared signing_keys table)
    |
    +-- OneAuth Server :9999        (user auth, app registration, key management)
    +-- Resource-Server-A :4001     (validates JWTs via shared KeyStore)
    +-- Resource-Server-B :4002     (validates JWTs via shared KeyStore)
    |
    +-- DrawApp :3001               (app #1 — registers, owns users, mints resource tokens)
    +-- ChatApp :3002               (app #2 — same binary, separate user database)
```

### Scenarios Exercised

| Scenario | What It Proves |
|----------|---------------|
| App auto-registration on startup | App calls `POST /apps/register`, gets `client_id` + `client_secret`, persists to disk |
| Independent user databases | DrawApp and ChatApp each have their own FS-backed user store — users don't overlap |
| Resource token minting | Authenticated app user clicks "Get Resource Token" → `MintResourceToken()` signs JWT with `client_secret` |
| Token validation by resource server | JWT POSTed to resource server's `/validate` → server looks up `client_id` in shared KeyStore, verifies HMAC |
| Cross-resource-server validation | Token from DrawApp validates on both Resource-Server-A and Resource-Server-B (they share the same KeyStore) |
| Cross-app isolation | Token signed with DrawApp's secret but claiming ChatApp's `client_id` is rejected (signature mismatch) |
| Token introspection | Resource server returns `user_id`, `client_id`, `scopes`, `max_rooms`, `max_msg_rate` from JWT custom claims |
| WebSocket-style auth | `GET /ws?token=...` validates token via query param (simulates WebSocket upgrade) |

### Running the Demo

**Option A: Live-reload development** (recommended for iterating)
```bash
cd demo
make dev       # PG in Docker, all Go services native with auto-rebuild
```

**Option B: Full Docker Compose**
```bash
cd demo
make up        # builds and starts all 6 services in Docker
make status    # shows URLs and container status
```

#### Manual Walkthrough

1. **http://localhost:9999** — OneAuth landing page. Sign up for an account. Dashboard shows registered apps.
2. **http://localhost:3001** — DrawApp. Sign up (separate user DB). After login, click "Get Resource Token". JWT claims display inline.
3. Click "Validate" — JWT is POSTed to Resource-Server-A. Response shows `valid: true` with user ID and claims.
4. **http://localhost:4001** — Resource-Server-A status page. See the validation in the log table.
5. **http://localhost:4001/test** — Paste any JWT to test manually.
6. **http://localhost:3002** — ChatApp. Repeat flow. Try validating against Resource-Server-B at `:4002`.

#### Automated Tests

```bash
# From repo root, with demo stack running:
DEMO_SERVER_URL=http://localhost:9999 \
DEMO_RESOURCE_SERVER_A_URL=http://localhost:4001 \
DEMO_RESOURCE_SERVER_B_URL=http://localhost:4002 \
DEMO_ADMIN_KEY=demo-admin-key-12345 \
uv run pytest tests/integration/test_05_browser_auth.py \
              tests/integration/test_06_federated_flow.py \
              tests/integration/test_07_multi_host.py \
              tests/integration/test_08_token_refresh.py -v
```

### What the Demo Simplifies (vs. Production)

| Demo Simplification | Production Reality |
|---------------------|-------------------|
| **In-memory app metadata** — `AppRegistrar.apps` map is lost on restart. Signing keys survive (in PostgreSQL) but metadata like domain, quotas, created_at is gone. | Persist app registrations in a database (`AppStore` interface — not yet implemented). |
| **FS-backed user stores** — each app stores users on disk under `/data/{name}/`. | Use GORM or GAE stores behind a real database. FS stores don't work in clusters. |
| **HS256 only** — all tokens use symmetric HMAC signing. The resource server needs the same secret as the app. | Asymmetric signing (RS256/ES256, issue #4) lets apps keep private keys secret. Resource server only needs public keys. |
| **No JWKS** — resource server reads keys from PostgreSQL directly. | JWKS endpoint (issue #7) lets resource servers auto-discover public keys via HTTP without shared database access. |
| **Single PostgreSQL** — all services share one database instance. | Separate read replicas, or JWKS-based discovery, or each resource server has its own KeyStore sync. |
| **Static quotas** — `max_rooms` and `max_msg_rate` are set at registration time and hardcoded in token minting. | Dynamic quotas from a billing/entitlement system. |
| **No token refresh** — resource tokens expire in 15 minutes, app mints a fresh one each time. | Client-side refresh loop or server-side refresh grant for long-lived sessions. |
| **No TLS** — all traffic is plaintext HTTP on localhost. | TLS everywhere. Secrets encrypted at rest. |
| **Hardcoded admin key** — `demo-admin-key-12345` in docker-compose env. | Admin key from secrets manager (e.g., GCP Secret Manager). Rotated regularly. |
| **Cookie-based sessions** — apps use HttpOnly cookie JWTs for browser sessions. | Works for browsers but blocks SPA/mobile clients (see Phase 3 OAuth API Mode below). |

### Key Architecture Points

**Trust anchor**: The shared `signing_keys` table. This is the only thing that connects apps and resource servers. Written by oneauth-server at registration, read by resource servers at validation.

**Secret shown once**: `POST /apps/register` returns `client_secret` exactly once. It's stored in the KeyStore as bytes but never returned again via any API. Apps must persist it (demo-hostapp saves to `app_credentials.json`).

**Resource server independence**: Once keys are in the shared KeyStore, resource servers validate tokens with zero runtime dependency on the auth server or apps. The resource server only needs database access.

**Credential recovery**: On startup, demo apps verify their cached credentials against the auth server (`GET /apps/{client_id}`). If the auth server doesn't recognize them (e.g., database was reset), the app deletes its stale credentials and re-registers automatically.

---

## Scenario: OAuth API Mode (Not Yet Implemented)

**Status**: P0 blocker — see [NEXTSTEPS.md](NEXTSTEPS.md), Phase 3

### The Problem

The current OAuth flow (Google/GitHub login) is browser-only:

1. Redirect to provider (stores state in cookie)
2. Provider redirects back to callback (reads state from cookie)
3. Callback sets `oa_token` HttpOnly cookie and redirects to `/dashboard`

Every step requires browser cookies and HTTP redirects. SPAs doing `fetch()` and mobile apps using deep links cannot participate.

`APIAuth` already returns proper `{access_token, refresh_token}` JSON — but only for password-based login (`grant_type=password`). There is no path from "OAuth succeeded" to "here are your API tokens."

### What Would Be Demonstrated

| Scenario | Flow |
|----------|------|
| SPA OAuth login | React app calls `/auth/google/callback?mode=api` → receives `{access_token, refresh_token}` JSON |
| Mobile OAuth | iOS opens Google OAuth in Safari → deep link `myapp://auth?code=xyz` → app exchanges code for tokens via `POST /api/token` |
| PKCE | Public client generates `code_verifier` + `code_challenge`, server validates on exchange |

### Prerequisites

- Phase 3 implementation (API mode OAuth callbacks, token exchange endpoint, PKCE)
- A demo SPA or mobile client that drives the flow

---

## Future Demos

| Demo | Scenario | Depends On |
|------|----------|------------|
| Asymmetric resource server auth | App uses RS256 private key, resource server validates with public key only | Issue #4 |
| JWKS discovery | Resource server auto-fetches app public keys via `.well-known/jwks.json` | Issue #7 |
| Client SDK | CLI tool authenticates, gets tokens, makes authenticated API calls | Client SDK migration (lilbattle) |
| Multi-factor auth | Login with password + TOTP code from authenticator app | MFA implementation |
