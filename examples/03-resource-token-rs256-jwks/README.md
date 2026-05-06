# 03: Resource Token with RS256 + JWKS Discovery

Non-UI · No infrastructure needed · Builds on Example 02

Asymmetric variant. The app generates an RSA key pair, registers only
the public key, and the resource server discovers it via JWKS — the
private key never leaves the app.

## Two-process architecture

`main.go` boots:
- An auth server with `/apps/` registration **and** `/.well-known/jwks.json`
- A resource server whose `JWKSKeyStore` fetches the AS's JWKS over HTTP and caches it (with background refresh — same pattern Keycloak / Auth0 / Authlete clients use).

In `--serve` mode they bind on real ports and the RS hits the AS over
real HTTP. The walkthrough is a client that registers a fresh app and
mints a token signed with its own private key.

## Quick start

```bash
make demo       # interactive walkthrough
make serve      # auth :8081, resource :8082 — point external clients at them
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

[04 — Discovery](../04-discovery/) — clients auto-discover endpoints
(token, JWKS, introspection) via `/.well-known/oauth-authorization-server`.
The interop foundation.
