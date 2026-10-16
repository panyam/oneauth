# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. No active mission (`queue.sh`: 1 open, 0 active; JARM #409 is parked).
- This run: dropped fix/88-keys-2 (PR #420 merged); tagged v0.1.47. Code scanning: 0 open alerts.

## Across threads

- #88 is worked one audit area at a time; DPoP, the HTTP surface and token security are done, and so is key management (`docs/SECURITY_AUDIT.md`). Next on #88: input validation and RFC rows (scope / RAR enforcement, body limits, error leaks; then authorize / DCR / PAR / metadata), then the rest of FAPI. Retired-key JWKS publishing is #421. HTTP-surface leftovers are #408.
- Token-slice follow-ups not filed, still candidates: real logout tokens / ID-JAGs at the middleware (e2e), revocation parity with Keycloak, GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- GAE store tests are deterministic now but still don't run in CI (they need an emulator service); no issue filed yet.
