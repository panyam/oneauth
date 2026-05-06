# 09: Key Rotation with Grace Periods

Non-UI · No infrastructure needed · Builds on Example 02

`KidStore` + `CompositeKeyLookup` keep the old signing key valid for a
configurable window after rotation, so in-flight tokens don't get
broken when an admin rotates an app's key.

## Two-process architecture

`main.go` boots:
- An auth server that exposes `POST /apps/{id}/rotate` — drives the rotation.
- A resource server whose middleware uses `CompositeKeyLookup{KeyStore, KidStore}` so tokens signed with the just-rotated-out key keep validating until the grace period expires.

## Quick start

```bash
make demo                              # interactive walkthrough
make serve                             # auth :8081, resource :8082

# Drive rotation by hand
curl -X POST http://localhost:8081/apps/<client_id>/rotate
```

The grace period in this demo is 100 ms — long enough to demonstrate
both states, short enough not to slow the demo down. Real deployments
use hours or days.

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

[10 — Security](../10-security/) — algorithm confusion (CVE-2015-9235),
cross-app token forgery, JWKS leak prevention.
