# Keycloak Interop Tests

Tests that prove OneAuth's `APIMiddleware` and `JWKSKeyStore` correctly validate tokens issued by [Keycloak](https://www.keycloak.org/) — a real-world OIDC Identity Provider.

## Quick Start

```bash
make upkcl      # Start Keycloak container (~15s startup)
make testkcl    # Run interop tests
make downkcl    # Stop when done
```

`make testkcl` auto-starts the container if it's not running.

## What's Tested

| Test | What it proves |
|------|---------------|
| OIDC Discovery | Keycloak's `/.well-known/openid-configuration` is parseable |
| JWKS Fetch & Parse | `JWKSKeyStore` correctly fetches and parses Keycloak's JWK keys |
| JWK → PublicKey | `utils.JWKToPublicKey` handles Keycloak's RSA key format |
| Token Validation (client_credentials) | `APIMiddleware` accepts Keycloak-issued JWTs |
| Token Validation (password grant) | User tokens from Keycloak validate correctly |
| kid Lookup | Keycloak's `kid` header resolves via `GetKeyByKid` |
| Audience Array | Keycloak's `aud` claim (string or array) handled correctly (#52) |
| Tampered Token Rejected | Modified Keycloak tokens fail signature verification |
| Wrong Credentials Rejected | Keycloak rejects invalid client_secret |

## Keycloak Realm Config

`realm.json` is imported on container startup. It contains:

- **Realm**: `oneauth-test` (RS256 signing)
- **Clients**:
  - `test-confidential` — client_credentials + password grants (secret: `test-secret-for-confidential-client`)
  - `test-public` — PKCE-enabled public client
  - `test-audience` — for audience validation tests
- **User**: `testuser` / `testpassword`
- **Scopes**: `relay-connect`, `relay-publish`, `read`, `write`

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `KEYCLOAK_URL` | `http://localhost:8180` | Keycloak base URL |

## Debugging

```bash
make kcllogs    # Tail Keycloak container logs
```

Admin console: http://localhost:8180/admin (admin/admin)

## CI

The Keycloak interop tests run as a **manual-trigger** GitHub Actions workflow (`workflow_dispatch`). They are not part of the regular CI pipeline to avoid slow builds.

To run in CI: Actions → "Keycloak Interop Tests" → "Run workflow"

## Architecture

These tests are a **separate Go module** (`tests/keycloak/go.mod`) to avoid leaking test dependencies into the core module. They import `oneauth/apiauth`, `oneauth/keys`, and `oneauth/utils` via a `replace` directive.

Tests skip gracefully when Keycloak is not running — `make test` and `make e2e` are unaffected.
