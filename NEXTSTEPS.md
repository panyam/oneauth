# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. Active mission: #98 (OIDF FAPI 2.0 Security Profile run), 2/6; next ready #439. Exercise last ran 2026-10-17 @ 9369845: 33/46 passed (`happy-flow` fails only on #440).
- This run: dropped feat/433-exercise-fapi2 (PR #442) and fix/438-login-next (PR #444); filed #443; #440 P2 → P1; tagged v0.2.3.

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #436 (refresh revocation leaves access tokens valid, P2).
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
