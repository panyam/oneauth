# Demos & Scenarios

Runnable demos that exercise key OneAuth scenarios end-to-end. Each section describes what the demo proves, how it simplifies things for clarity, and what changes in a real deployment.

---

## Demo 1: Federated Relay Auth

**Location**: `demo/` (Docker Compose) + `cmd/demo-hostapp/` + `cmd/demo-relay/`

### What It Demonstrates

Multiple independent applications ("Hosts") register with a central auth server, authenticate their own users independently, mint relay-scoped JWTs, and have those tokens validated by relay servers that share no direct connection to the host apps.

This answers the core question: **How does a relay server trust a JWT issued by an application it has never seen before?**

Answer: a shared PostgreSQL `signing_keys` table acts as the trust anchor. OneAuth server writes signing keys at host registration time. Relays read from it at validation time.

### Service Topology

```
PostgreSQL (shared signing_keys table)
    |
    +-- OneAuth Server :9999  (user auth, host registration, key management)
    +-- Relay-A :4001         (validates JWTs via shared KeyStore)
    +-- Relay-B :4002         (validates JWTs via shared KeyStore)
    |
    +-- DrawApp :3001         (host app #1 — registers, owns users, mints relay tokens)
    +-- ChatApp :3002         (host app #2 — same binary, separate user database)
```

### Scenarios Exercised

| Scenario | What It Proves |
|----------|---------------|
| Host auto-registration on startup | Host calls `POST /hosts/register`, gets `client_id` + `client_secret`, persists to disk |
| Independent user databases | DrawApp and ChatApp each have their own FS-backed user store — users don't overlap |
| Relay token minting | Authenticated host user clicks "Get Relay Token" → `MintRelayToken()` signs JWT with `client_secret` |
| Token validation by relay | JWT POSTed to relay's `/validate` → relay looks up `client_id` in shared KeyStore, verifies HMAC |
| Cross-relay validation | Token from DrawApp validates on both Relay-A and Relay-B (they share the same KeyStore) |
| Cross-host isolation | Token signed with DrawApp's secret but claiming ChatApp's `client_id` is rejected (signature mismatch) |
| Token introspection | Relay returns `user_id`, `client_id`, `scopes`, `max_rooms`, `max_msg_rate` from JWT custom claims |
| WebSocket-style auth | `GET /ws?token=...` validates token via query param (simulates WebSocket upgrade) |

### Running the Demo

```bash
cd demo
make up        # builds and starts all 6 services
make status    # shows URLs and container status
```

#### Manual Walkthrough

1. **http://localhost:9999** — OneAuth landing page. Sign up for an account. Dashboard shows registered hosts.
2. **http://localhost:3001** — DrawApp. Sign up (separate user DB). After login, click "Get Relay Token". JWT claims display inline.
3. Click "Validate" — JWT is POSTed to Relay-A. Response shows `valid: true` with user ID and claims.
4. **http://localhost:4001** — Relay-A status page. See the validation in the log table.
5. **http://localhost:4001/test** — Paste any JWT to test manually.
6. **http://localhost:3002** — ChatApp. Repeat flow. Try validating against Relay-B at `:4002`.

#### Automated Tests

```bash
# From repo root, with demo stack running:
DEMO_SERVER_URL=http://localhost:9999 \
DEMO_RELAY_A_URL=http://localhost:4001 \
DEMO_RELAY_B_URL=http://localhost:4002 \
DEMO_ADMIN_KEY=demo-admin-key-12345 \
uv run pytest tests/integration/test_05_browser_auth.py \
              tests/integration/test_06_federated_flow.py \
              tests/integration/test_07_multi_host.py \
              tests/integration/test_08_token_refresh.py -v
```

### What the Demo Simplifies (vs. Production)

| Demo Simplification | Production Reality |
|---------------------|-------------------|
| **In-memory host metadata** — `HostRegistrar.hosts` map is lost on restart. Signing keys survive (in PostgreSQL) but metadata like domain, quotas, created_at is gone. | Persist host registrations in a database (`HostStore` interface — not yet implemented). |
| **FS-backed user stores** — each host app stores users on disk under `/data/{name}/`. | Use GORM or GAE stores behind a real database. FS stores don't work in clusters. |
| **HS256 only** — all tokens use symmetric HMAC signing. The relay needs the same secret as the host. | Asymmetric signing (RS256/ES256, issue #4) lets hosts keep private keys secret. Relay only needs public keys. |
| **No JWKS** — relay reads keys from PostgreSQL directly. | JWKS endpoint (issue #7) lets relays auto-discover public keys via HTTP without shared database access. |
| **Single PostgreSQL** — all services share one database instance. | Separate read replicas, or JWKS-based discovery, or each relay has its own KeyStore sync. |
| **Static quotas** — `max_rooms` and `max_msg_rate` are set at registration time and hardcoded in token minting. | Dynamic quotas from a billing/entitlement system. |
| **No token refresh** — relay tokens expire in 15 minutes, host app mints a fresh one each time. | Client-side refresh loop or server-side refresh grant for long-lived sessions. |
| **No TLS** — all traffic is plaintext HTTP on localhost. | TLS everywhere. Secrets encrypted at rest. |
| **Hardcoded admin key** — `demo-admin-key-12345` in docker-compose env. | Admin key from secrets manager (e.g., GCP Secret Manager). Rotated regularly. |
| **Cookie-based sessions** — host apps use HttpOnly cookie JWTs for browser sessions. | Works for browsers but blocks SPA/mobile clients (see Phase 3 OAuth API Mode below). |

### Key Architecture Points

**Trust anchor**: The shared `signing_keys` table. This is the only thing that connects hosts and relays. Written by oneauth-server at registration, read by relays at validation.

**Secret shown once**: `POST /hosts/register` returns `client_secret` exactly once. It's stored in the KeyStore as bytes but never returned again via any API. Host apps must persist it (demo-hostapp saves to `host_credentials.json`).

**Relay independence**: Once keys are in the shared KeyStore, relays validate tokens with zero runtime dependency on the auth server or host apps. The relay only needs database access.

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
| Asymmetric relay auth | Host uses RS256 private key, relay validates with public key only | Issue #4 |
| JWKS discovery | Relay auto-fetches host public keys via `.well-known/jwks.json` | Issue #7 |
| Client SDK | CLI tool authenticates, gets tokens, makes authenticated API calls | Client SDK migration (lilbattle) |
| Multi-factor auth | Login with password + TOTP code from authenticator app | MFA implementation |
