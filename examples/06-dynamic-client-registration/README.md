# 06: Dynamic Client Registration

Non-UI | No infrastructure needed | Builds on Example 04

## What you'll learn

- **Start auth server with DCR endpoint** — The auth server serves /apps/dcr (RFC 7591) alongside the proprietary /apps/register. Both create clients in the same KeyStore.
- **Register a symmetric client (client_secret_post)** — The simplest DCR: the AS generates both a client_id and client_secret. The client uses client_secret_post to authenticate at the token endpoint.
- **Get a token with the DCR-registered client** — The dynamically registered client works exactly like a manually registered one — the AS doesn't distinguish between registration methods.
- **Register an asymmetric client (private_key_jwt with JWKS)** — For asymmetric auth, the client sends its public key as a JWK set. No secret is returned — the client authenticates with signed JWTs using its private key.
- **Register via Keycloak DCR (optional)** — Same DCR request format against Keycloak. KC returns additional fields like registration_access_token for client management. If KC isn't running, this step is skipped.

## Flow

```mermaid
sequenceDiagram
    participant App as New App
    participant AS as Auth Server

    Note over App,AS: Step 1: Start auth server with DCR endpoint

    Note over App,AS: Step 2: Register a symmetric client (client_secret_post)
    App->>AS: POST /apps/dcr {client_name, grant_types, auth_method}
    AS-->>App: {client_id, client_secret, client_id_issued_at}

    Note over App,AS: Step 3: Get a token with the DCR-registered client
    App->>AS: POST /api/token {client_id, client_secret from DCR}
    AS-->>App: {access_token}

    Note over App,AS: Step 4: Register an asymmetric client (private_key_jwt with JWKS)
    App->>AS: POST /apps/dcr {auth_method: private_key_jwt, jwks: {keys: [...]}}
    AS-->>App: {client_id} (no client_secret — asymmetric!)

    Note over App,AS: Step 5: Register via Keycloak DCR (optional)
    App->>AS: POST {KC registration_endpoint} {client_name, grant_types}
    AS-->>App: {client_id, client_secret, registration_access_token}
```

## Steps

### About this example

**Actors:** App (a new third-party integration), Auth Server (AS).
Think: a developer builds a new Slack bot and registers it via API — no admin dashboard needed.
[What are these?](../README.md#cast-of-characters)

In Examples 01-05, we registered via `/apps/register` — OneAuth's proprietary
endpoint. RFC 7591 defines a standard registration API that works across providers:

| Endpoint | Standard | Works with |
|----------|----------|-----------|
| `/apps/register` | OneAuth proprietary | OneAuth only |
| `/apps/dcr` | RFC 7591 | OneAuth, Keycloak, Auth0, any compliant AS |

DCR lets apps self-register by posting their metadata (name, redirect URIs,
grant types, auth method). The AS creates the client and returns credentials.

### Step 1: Start auth server with DCR endpoint

> **References:** [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591), [RFC 8414 — AS Metadata Discovery](https://www.rfc-editor.org/rfc/rfc8414)

The auth server serves /apps/dcr (RFC 7591) alongside the proprietary /apps/register. Both create clients in the same KeyStore.

### DCR request format (RFC 7591 §2)

A DCR request is a JSON object with client metadata:
```json
{
  "client_name": "My Bot",
  "client_uri": "https://mybot.example.com",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_post",
  "scope": "read write"
}
```

The AS responds with the registered client metadata plus generated credentials:
```json
{
  "client_id": "app_abc123...",
  "client_secret": "7f3e8a...",
  "client_id_issued_at": 1700000000,
  "client_name": "My Bot",
  "token_endpoint_auth_method": "client_secret_post"
}
```

### Step 2: Register a symmetric client (client_secret_post)

> **References:** [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)

The simplest DCR: the AS generates both a client_id and client_secret. The client uses client_secret_post to authenticate at the token endpoint.

### Step 3: Get a token with the DCR-registered client

> **References:** [RFC 6749 §4.4 — Client Credentials Grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)

The dynamically registered client works exactly like a manually registered one — the AS doesn't distinguish between registration methods.

### Step 4: Register an asymmetric client (private_key_jwt with JWKS)

> **References:** [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591), [RFC 7517 — JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)

For asymmetric auth, the client sends its public key as a JWK set. No secret is returned — the client authenticates with signed JWTs using its private key.

### Symmetric vs asymmetric DCR

| | client_secret_post / basic | private_key_jwt |
|---|---|---|
| **DCR sends** | Just metadata | Metadata + JWKS (public key) |
| **AS returns** | client_id + client_secret | client_id only (no secret) |
| **Token auth** | Send secret in request | Sign a JWT with private key |
| **Key in JWKS** | Not in JWKS (secret) | Public key served in JWKS |
| **Best for** | Simple integrations | High-security, multi-service |

### Step 5: Register via Keycloak DCR (optional)

> **References:** [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)

Same DCR request format against Keycloak. KC returns additional fields like registration_access_token for client management. If KC isn't running, this step is skipped.

### What's next?

In [07 — Client SDK](../07-client-sdk/), you'll see production patterns:
automatic token caching, background refresh, scope step-up, and discovery-driven
configuration — all wrapped in a simple `TokenSource` interface.

## References

- [RFC 7517 — JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- [RFC 8414 — AS Metadata Discovery](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 6749 §4.4 — Client Credentials Grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)

## Run it

```bash
go run ./examples/06-dynamic-client-registration/
```

Pass `--non-interactive` to skip pauses:

```bash
go run ./examples/06-dynamic-client-registration/ --non-interactive
```
