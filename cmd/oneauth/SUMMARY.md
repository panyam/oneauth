# cmd/oneauth — OAuth client CLI

Cobra-based CLI that wraps the `client/` SDK and dogfoods
`apiauth.IntrospectionValidator`. Ships `token`, `introspect`, `dcr`,
and `jwks` against any RFC 8414 / OIDC-compliant authorization server.

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
- **cmd/token_device.go** — `oneauth token device <issuer>` — RFC 8628
  device authorization grant. Discovers `device_authorization_endpoint`,
  prints `user_code` + verification URL to stderr, polls until approve
  / deny / expire (honoring `slow_down`), emits via existing emitters.
  `--open` launches the verification URL in the default browser; `--qr`
  renders an ASCII QR code via `qrterminal/v3` for phone hand-off
  (issue 268).
- **cmd/introspect.go** — `oneauth introspect <issuer>` — RFC 7662 token
  introspection via `apiauth.IntrospectionValidator`. `--format active`
  prints just `true|false` for shell predicates (issue 258).
- **cmd/dcr.go** — `oneauth dcr register|get|put|delete <issuer>` —
  RFC 7591 registration + RFC 7592 management. Wraps
  `client.RegisterClient`, `client.GetRegistration`,
  `client.UpdateRegistration`, `client.DeleteRegistration` (issue 258).
- **cmd/jwks.go** — `oneauth jwks <issuer>` — fetch + pretty-print
  RFC 7517 JSON Web Key Set. `--kid` and `--sig-only` filters; `--format
  table` for a human-scan-friendly summary (issue 258).
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

- Issues: panyam/oneauth issue 255 (token), 258 (introspect / dcr / jwks).
- Library entry points: `client.AuthClient.LoginWithBrowser`,
  `client.AuthClient.ClientCredentials`, `client.AuthClient.Login`,
  `client.AuthClient.RefreshToken`, `client.RegisterClient` /
  `GetRegistration` / `UpdateRegistration` / `DeleteRegistration`,
  `apiauth.IntrospectionValidator`.
