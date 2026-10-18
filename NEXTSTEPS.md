# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. Active mission: #98 (OIDF FAPI 2.0 Security Profile run), 3/6; next ready #439. Exercise last ran 2026-10-17 @ e012a7b: 35/46 passed, `happy-flow` included.
- This run: dropped fix/440-tls-bcp195 (PR #445, #440 closed); tagged v0.2.4.

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #436 (refresh revocation leaves access tokens valid, P2).
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
