# cmd/oneauth — OAuth client CLI

Cobra-based CLI that wraps the `client/` SDK. First-shipped surface is
the `token` subcommand for acquiring OAuth 2.0 access tokens against
any RFC 8414 / OIDC-compliant authorization server.

## Contents

- **main.go** — `package main` entrypoint; delegates to `cmd.NewRoot()`.
- **cmd/root.go** — `NewRoot()` constructs the Cobra tree.
- **cmd/token.go** — `oneauth token` parent: persistent `--format` flag,
  shared helpers (`newAuthClient`, `splitScopes`, `readStdinSecret`).
- **cmd/token_browser.go** — `oneauth token browser <issuer>` —
  authorization code + PKCE (RFC 8252 + RFC 7636). `--no-browser` mode
  prints the auth URL to stderr.
- **cmd/token_client_credentials.go** — `oneauth token client-credentials
  <issuer>` — RFC 6749 §4.4 grant. Aliased as `cc`.
- **cmd/token_password.go** — `oneauth token password <issuer>` — RFC
  6749 §4.3 ROPC grant; prints a deprecation banner to stderr.
- **cmd/token_refresh.go** — `oneauth token refresh <issuer>` — RFC 6749
  §6 refresh_token grant. Calls `client.AuthClient.RefreshToken`.
- **cmd/format.go** — JSON / bash / access-token-only emitters.

## Module structure

Separate Go sub-module (`github.com/panyam/oneauth/cmd/oneauth`) with a
`replace` directive pointing back at the workspace root. This keeps
Cobra + pflag out of the root `github.com/panyam/oneauth` library's
dependency graph — downstream library consumers don't pull CLI deps.

## Testing

- **cmd/*_test.go** — unit tests against an in-process synthetic AS.
- **`tests/keycloak/oneauth_cli_test.go`** — wire-format coverage
  against a real Keycloak (shells out to a freshly-built binary).

## See

- Issue: panyam/oneauth issue 255
- Library entry points: `client.AuthClient.LoginWithBrowser`,
  `client.AuthClient.ClientCredentials`, `client.AuthClient.Login`,
  `client.AuthClient.RefreshToken`.
