# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. No active mission (`queue.sh`: JARM #409 is parked).
- This run: dropped docs/88-closing (PR #430 merged; #88 and #327 closed); tagged v0.1.56.

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups are #421 (retired keys in JWKS) and #429 (revoke tokens from a reused code, GAE store tests in CI), both waiting.
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
