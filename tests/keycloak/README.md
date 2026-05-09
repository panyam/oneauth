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
| RFC 7592 lifecycle (#171) | `client.GetRegistration` / `UpdateRegistration` / `DeleteRegistration` SDK helpers round-trip against Keycloak's `clients-registrations/openid-connect/{client_id}` endpoint, including registration_access_token rotation on PUT and rejection of the rotated-out token |

## Keycloak Realm Config

`realm.json` is imported on container startup. It contains:

- **Realm**: `oneauth-test` (RS256 signing)
- **Anonymous DCR / RFC 7592 management**: enabled via a relaxed `Trusted Hosts` policy in the `components` block. `host-sending-registration-request-must-match` and `client-uris-must-match` are both `false` because Docker-on-macOS makes the request appear to come from a non-loopback IP, which would otherwise trip the default policy. **Test-only** — production deployments should use Initial Access Tokens.
- **Clients**:
  - `test-confidential` — client_credentials + password grants (secret: `test-secret-for-confidential-client`)
  - `test-public` — PKCE-enabled public client
  - `test-audience` — for audience validation tests
  - `test-pkjwt` — `client-jwt` (private_key_jwt) for #158 interop. Public key is checked into `realm.json`; matching private key lives in `testdata/client-jwt.private.pem`. **Test-only fixture — never use this key in production.** Secret-scanner false positive: allowlist this path.
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
