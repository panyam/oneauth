# 01: Client Credentials Flow

Non-UI | No infrastructure needed | RFC 6749 §4.4

## What you'll learn

- **Register a client** — The client receives credentials it will use to authenticate in the next step. Open registration (`NewNoAuth`) is for the demo only — gate this in production.
- **Request an access token** — The AS verifies the client credentials and returns a signed JWT. The token carries sub=client_id (no user context in this flow).
- **Access a protected resource** — The resource server validates the JWT signature and extracts claims from it. No network call to the auth server.
- **Access without a token (expect rejection)** — Without a valid Bearer token, the resource server rejects the request.

## Flow

```mermaid
sequenceDiagram
    participant App as Client App
    participant AS as Auth Server
    participant RS as Resource Server

    Note over App,RS: Step 1: Register a client
    App->>AS: POST /apps/register {domain, signing_alg}
    AS-->>App: {client_id, client_secret}

    Note over App,RS: Step 2: Request an access token
    App->>AS: POST /api/token {grant_type: client_credentials}
    AS-->>App: {access_token, token_type, expires_in}

    Note over App,RS: Step 3: Access a protected resource
    App->>RS: GET /resource (Authorization: Bearer token)
    RS->>RS: Validate JWT signature + claims
    RS-->>App: 200 {data}

    Note over App,RS: Step 4: Access without a token (expect rejection)
    App->>RS: GET /resource (no Authorization header)
    RS-->>App: 401 Unauthorized
```

## Steps

### About this example

**Actors:** App (a bot), Auth Server (AS), Resource Server (RS).
Think: a GitHub bot posting to Slack's API. [What are these?](../README.md#cast-of-characters)

The `client_credentials` grant is the standard OAuth 2.0 machine-to-machine
flow. No user is involved — the bot authenticates directly with its own
credentials and receives an access token.

Common use cases: service-to-service calls, background jobs, CLI tools.

This walkthrough acts as a scripted OAuth client. The auth server and
resource server it talks to are the same code `make serve` boots — see
`main.go`. Run `make serve` in another terminal and you can replay every
step on the wire with the `curl` blocks shown below.

### Step 1: Register a client

> **References:** [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)

The client receives credentials it will use to authenticate in the next step. Open registration (`NewNoAuth`) is for the demo only — gate this in production.

#### Reproduce on the wire

```bash
curl -s -X POST http://localhost:8081/apps/register \
  -H 'Content-Type: application/json' \
  -d '{"client_domain":"my-service.example.com","signing_alg":"HS256"}'
```

### Step 2: Request an access token

> **References:** [RFC 6749 §4.4 — Client Credentials Grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4), [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)

The AS verifies the client credentials and returns a signed JWT. The token carries sub=client_id (no user context in this flow).

#### Reproduce on the wire

```bash
curl -s -X POST http://localhost:8081/api/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=<from previous step>' \
  -d 'client_secret=<from previous step>' \
  -d 'scope=read write'
```

### What's in the JWT?

The access token is a signed JWT containing:
- `sub`: the client_id (who this token represents)
- `scopes`: the granted scopes
- `iss`: the issuer URL
- `exp`/`iat`: expiry and issued-at timestamps
- `jti`: unique token ID (for revocation)

The resource server can validate this token locally by checking the
signature — no callback to the auth server needed.

### Step 3: Access a protected resource

> **References:** [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750), [RFC 7515 — JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515)

The resource server validates the JWT signature and extracts claims from it. No network call to the auth server.

#### Reproduce on the wire

```bash
curl -s http://localhost:8082/resource \
  -H "Authorization: Bearer <access_token from previous step>"
```

### Step 4: Access without a token (expect rejection)

> **References:** [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)

Without a valid Bearer token, the resource server rejects the request.

#### Reproduce on the wire

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8082/resource
```

### What's next?

In [02 — Resource Token (HS256)](../02-resource-token-hs256/), you'll see
how a registered app can mint tokens *for individual users*, not just for
itself. This is the federated authentication pattern used by OneAuth's
multi-app architecture.

## References

- [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- [RFC 6749 §4.4 — Client Credentials Grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
- [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 7515 — JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515)

## Run it

```bash
go run ./examples/01-client-credentials/
```

Pass `--non-interactive` to skip pauses:

```bash
go run ./examples/01-client-credentials/ --non-interactive
```
