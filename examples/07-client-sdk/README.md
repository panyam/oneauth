# 07: Client SDK — Production Patterns

Non-UI · No infrastructure needed · Builds on Examples 01-06

Production token-acquisition patterns: discovery-driven configuration,
automatic token caching, scope step-up — all behind the `TokenSource`
interface. Same SDK works against OneAuth and Keycloak.

## Two-process architecture

`main.go` boots an auth server (registration + token + discovery) and
a resource server. The walkthrough uses `client.AuthClient` and
`client.ClientCredentialsSource` — the same library code your apps
import in production.

## Quick start

```bash
make demo                              # interactive walkthrough
make serve                             # auth :8081, resource :8082
```

## Optional: against Keycloak

```bash
cd ..  && make upkcl
cd 07-client-sdk && make demo          # last step uses the SDK against KC
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

[08 — Rich Authorization Requests](../08-rich-authorization-requests/) —
RFC 9396 fine-grained permissions beyond flat scopes.
