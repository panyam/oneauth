# OneAuth Federated Auth Demo

End-to-end demo of OneAuth's federated authentication: two host apps register with a central auth server, mint relay-scoped JWTs, and two relays validate those tokens via a shared PostgreSQL KeyStore.

## Architecture

```
PostgreSQL (shared signing_keys table)
    |
    +-- OneAuth Server :9999  (user auth, host registration, JWT issuing)
    +-- Relay-A :4001         (validates JWTs via shared KeyStore)
    +-- Relay-B :4002         (validates JWTs via shared KeyStore)
    |
    +-- DrawApp :3001         (registers as host, owns users, mints relay tokens)
    +-- ChatApp :3002         (registers as host, owns users, mints relay tokens)
```

## Quick Start

```bash
cd demo
make up        # builds and starts all 6 services
make status    # shows URLs and container status
```

## Walkthrough

1. **Browse to http://localhost:9999** — OneAuth landing page. Sign up for an account.
2. **Browse to http://localhost:3001** (DrawApp) — Sign up with a different email. Log in.
3. **Click "Get Relay Token"** — Shows a JWT signed with DrawApp's client secret.
4. **Click "Validate"** — Sends the JWT to relay-a for validation.
5. **Browse to http://localhost:3002** (ChatApp) — Same flow, different client_id.
6. **Both tokens validate on both relays** — because relays share the same KeyStore.
7. **Browse to http://localhost:4001/test** — Paste any token to test manually.

## Environment Variables

Copy `.env.example` to `.env` to customize:

| Variable | Default | Purpose |
|----------|---------|---------|
| `POSTGRES_PASSWORD` | `oneauth-demo-pass` | PostgreSQL password |
| `ADMIN_API_KEY` | `demo-admin-key-12345` | Admin key for host registration |
| `JWT_SECRET_KEY` | `demo-jwt-secret-key-change-me` | OneAuth server session signing |

## Commands

```bash
make up       # Start all services
make down     # Stop all services
make logs     # Tail logs
make rebuild  # Force rebuild and restart
make clean    # Stop and remove volumes (full reset)
make status   # Show URLs and container status
```
