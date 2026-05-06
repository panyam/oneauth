# 05: Token Introspection

Non-UI · No infrastructure needed · [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)

The RS asks the AS "is this token still valid?" instead of decoding the
JWT itself. Catches revocation immediately, works with opaque tokens,
costs an HTTP round-trip per call. Hybrid (local-then-introspect) is the
production sweet spot.

## Two-process architecture

`main.go` boots an auth server with `/api/token` + `/oauth/introspect` +
an `InMemoryBlacklist`. With `--serve`, the introspection endpoint
binds on a real port — any RS (`curl`, your service, etc.) can post a
token and get back `{active: true/false, ...}`.

## Quick start

```bash
make demo                              # interactive walkthrough
make serve                             # auth :8081

# in another terminal — introspect a token by hand
curl -s -u "<client_id>:<client_secret>" \
  -d "token=<access_token>" \
  http://localhost:8081/oauth/introspect | jq
```

## Optional: against Keycloak

```bash
cd ..  && make upkcl
cd 05-introspection && make demo       # last step compares the same flow on KC
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for the full step-by-step including
revocation, unauthenticated rejection, and Keycloak parity.

## Targets

| `make …` | What |
|---|---|
| `demo` (default) | Walkthrough with TUI renderer |
| `demo-plain` | Plain renderer |
| `demo-ci` | Non-interactive |
| `serve` | Bind AS on a real port |
| `walkthrough` | Regenerate `WALKTHROUGH.md` |

## What's next

[06 — Dynamic Client Registration](../06-dynamic-client-registration/) —
RFC 7591 self-service client onboarding.
