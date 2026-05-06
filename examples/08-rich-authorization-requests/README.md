# 08: Rich Authorization Requests

Non-UI · No infrastructure needed · [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)

Fine-grained, structured `authorization_details` on the token endpoint
— what banks, fintechs, and any regulated industry need beyond flat
scopes. The Payments API and Accounts API enforce different RAR types,
proving a payment token can't read accounts.

## Three-server architecture

`main.go` boots three real servers:
- **Auth Server** — token endpoint, introspection, AS metadata advertising `authorization_details_types_supported`
- **Payments API** — `RequireAuthorizationDetails("payment_initiation")` middleware
- **Accounts API** — `RequireAuthorizationDetails("account_information")` middleware

With `--serve`, all three bind on real ports (`:8081`/`:8082`/`:8083`).

## Quick start

```bash
make demo                              # interactive walkthrough
make serve                             # AS :8081, payments :8082, accounts :8083
```

## Optional: cross-server with the RAR test issuer

```bash
cd ../.. && make uprar                 # cmd/rar-test-issuer on :8181
cd examples/08-rich-authorization-requests && make demo
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for the full step-by-step.

## Targets

| `make …` | What |
|---|---|
| `demo` (default) | Walkthrough with TUI renderer |
| `demo-plain` | Plain renderer |
| `demo-ci` | Non-interactive |
| `serve` | Bind AS + Payments + Accounts on real ports |
| `walkthrough` | Regenerate `WALKTHROUGH.md` |

## What's next

[09 — Key Rotation](../09-key-rotation/) — rotate signing keys with a
grace period.
