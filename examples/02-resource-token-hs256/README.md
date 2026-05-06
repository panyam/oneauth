# 02: Resource Token with HS256 (Federated Auth)

Non-UI · No infrastructure needed · Builds on Example 01

A registered app mints JWTs **for individual users**, not for itself.
The resource server validates with the same KeyStore the app's secret
is registered into. This is OneAuth's federated-auth pattern.

## Two-process architecture

`main.go` boots an auth server (`AppRegistrar`) and a resource server
sharing an in-process `KeyStore`. With `--serve`, both bind on real
ports — any client can register an app and mint tokens. The walkthrough
is one such client; it spins up the same servers in-process via
`httptest`.

## Quick start

```bash
make demo                # interactive walkthrough (TUI)
make serve               # auth :8081, resource :8082
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for the full step-by-step with
sequence diagram and copy-paste reproductions.

## Targets

| `make …` | What |
|---|---|
| `demo` (default) | Interactive walkthrough with the TUI renderer |
| `demo-plain` | Plain stdout renderer |
| `demo-ci` | Non-interactive |
| `serve` | Bind AS + RS on real ports and block |
| `walkthrough` | Regenerate `WALKTHROUGH.md` |

## What's next

[03 — RS256 + JWKS](../03-resource-token-rs256-jwks/) — asymmetric
signing. The app registers a public key, serves it via JWKS, and the RS
discovers it automatically. No shared secrets.
