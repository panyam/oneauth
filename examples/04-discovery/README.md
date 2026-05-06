# 04: AS Metadata Discovery

Non-UI · No infrastructure needed · [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)

Auto-discover the AS's endpoints (token, JWKS, introspection,
registration) from a single well-known URL — same mechanism Keycloak,
Auth0, and Authlete use. The walkthrough also shows the same
`client.DiscoverAS()` call working against Keycloak (when running).

## Two-process architecture

`main.go` boots an auth server with the full discovery surface
(`/.well-known/openid-configuration`, token, JWKS, introspection,
registration) plus a resource server. With `--serve`, both bind on real
ports — any client can do `curl /.well-known/openid-configuration` and
go from there.

## Quick start

```bash
make demo                              # interactive walkthrough
make serve                             # auth :8081, resource :8082
curl -s http://localhost:8081/.well-known/openid-configuration | jq
```

## Optional: side-by-side with Keycloak

```bash
cd ..  && make upkcl                   # boots Keycloak on :8280
cd 04-discovery && make demo           # the last step compares both
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for the full step-by-step.

## Targets

| `make …` | What |
|---|---|
| `demo` (default) | Walkthrough with TUI renderer |
| `demo-plain` | Plain renderer |
| `demo-ci` | Non-interactive |
| `serve` | Bind AS + RS on real ports |
| `walkthrough` | Regenerate `WALKTHROUGH.md` |

## What's next

[05 — Introspection](../05-introspection/) — RS validates tokens by
asking the AS instead of decoding the JWT itself.
