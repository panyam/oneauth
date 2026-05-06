# 06: Dynamic Client Registration

Non-UI · No infrastructure needed · [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)

Self-service client onboarding via `POST /apps/dcr` — same request shape
works against OneAuth, Keycloak, and any compliant AS. Covers both
`client_secret_post` and `private_key_jwt` flows.

## Two-process architecture

`main.go` boots an auth server with `/apps/dcr` (RFC 7591) plus the
discovery, token, and JWKS endpoints needed for a freshly-registered
client to immediately mint tokens. With `--serve`, anyone (including the
walkthrough) can hit `/apps/dcr`.

## Quick start

```bash
make demo                              # interactive walkthrough
make serve                             # auth :8081

# Drive DCR by hand
curl -s -X POST http://localhost:8081/apps/dcr \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"Hand Demo","grant_types":["client_credentials"]}' | jq
```

## Optional: against Keycloak

```bash
cd ..  && make upkcl
cd 06-dynamic-client-registration && make demo  # last step posts DCR to KC
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for the full step-by-step.

## Targets

| `make …` | What |
|---|---|
| `demo` (default) | Walkthrough with TUI renderer |
| `demo-plain` | Plain renderer |
| `demo-ci` | Non-interactive |
| `serve` | Bind AS on a real port |
| `walkthrough` | Regenerate `WALKTHROUGH.md` |

## What's next

[07 — Client SDK](../07-client-sdk/) — production token-source patterns.
