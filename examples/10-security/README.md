# 10: Security — Attack Prevention

Non-UI · No infrastructure needed · Standalone

Live demonstrations of real JWT attacks and OneAuth's defenses:
algorithm confusion (CVE-2015-9235), `alg:none`, cross-app token
forgery, and JWKS leak prevention. Each attack runs end-to-end against
the strict middleware so you see both attack and defense fire.

## Two-process architecture

`main.go` boots:
- An auth/JWKS server on `:8081` (`/apps/register`, `/.well-known/jwks.json`)
- A protected resource on `:8082` validating with the strict middleware

In `--serve` mode you can fuzz the resource endpoint with crafted
tokens and verify the middleware blocks them in your environment too.

## Quick start

```bash
make demo                              # interactive walkthrough
make serve                             # auth :8081, resource :8082

# Fuzz it yourself
curl -s http://localhost:8082/resource -H "Authorization: Bearer <crafted-token>"
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

## End of the journey

You've completed all 10 examples. See `../README.md` for the full
learning path or jump back to [01](../01-client-credentials/).
