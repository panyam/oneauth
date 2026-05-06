# 01: Client Credentials Flow

Non-UI · No infrastructure needed · [RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)

The simplest way to get a token from OneAuth. A client authenticates
with its `client_id` and `client_secret` and receives a JWT access
token, then uses it as a Bearer token to call a protected resource.

## Two-process architecture

`main.go` builds the auth server and resource server. With `--serve`,
they bind to real ports and block — any OAuth client can drive them.
Without it, the binary spins up the same servers in-process via
`httptest` and runs the walkthrough (a scripted client) against them.
Same builders, same wire — the demo just drives them itself.

## Quick start

```bash
# Interactive walkthrough (TUI renderer)
make demo

# Or run the servers yourself and drive them with curl / your own client
make serve            # auth :8081, resource :8082
# in another terminal:
curl -s -X POST http://localhost:8081/apps/register \
  -H 'Content-Type: application/json' \
  -d '{"client_domain":"my.example.com","signing_alg":"HS256"}'
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for the full step-by-step with
sequence diagram, every wire-level call, and copy-paste curl
reproductions.

## Targets

| `make …` | What |
|---|---|
| `demo` (default) | Run the walkthrough with the TUI renderer |
| `demo-plain` | Plain stdout renderer (good for piping) |
| `demo-ci` | Non-interactive — every step fires without pauses |
| `serve` | Bind the AS + RS on real ports and block |
| `walkthrough` | Regenerate `WALKTHROUGH.md` from the demo definition |

## What's next

[02 — Resource Token (HS256)](../02-resource-token-hs256/) — registered
apps mint tokens **for individual users**, not just for themselves. The
federated auth pattern OneAuth was built for.
