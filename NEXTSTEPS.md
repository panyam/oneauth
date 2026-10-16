# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. No active mission (`queue.sh`: 1 open, 0 active; JARM #409 is parked).
- This run: dropped fix/codeql-warnings, fix/kc-id-token-as-access, fix/88-keys (PRs #417 to #419 merged); tagged v0.1.46.

## Across threads

- #88 is worked one audit area at a time; DPoP, the HTTP surface and token security are done, and key management is half done (`docs/SECURITY_AUDIT.md`, "Keys"). Next on #88: the second keys PR (KidStore encryption for retired keys, RSA ≥ 2048 on load, JWKS `use`/`key_ops` and 304 headers, the RFC 7638 vector test, `make audit` via pinned `go run`, a `CleanExpired` sweeper), then input validation and RFC rows, then the rest of FAPI. HTTP-surface leftovers are #408.
- Token-slice follow-ups not filed, still candidates: real logout tokens / ID-JAGs at the middleware (e2e), revocation parity with Keycloak, GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- GAE store tests are deterministic now but still don't run in CI (they need an emulator service); no issue filed yet.
