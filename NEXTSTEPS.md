# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. Mission #98 (OIDF FAPI 2.0 Security Profile run) is 7/7 with nothing left in its queue; it closes once the user signs off on the output. Exercise last ran 2026-10-18 @ 022cabb via `make testoidf`: 41 of 46 passed, 4 REVIEW with their evidence matched, 1 expected skip (RS256, #330), no regressions. After #98, no mission is active; JARM (#409) is parked, next ready #410.
- This run: no branch threads to prune (feat/447-fapi2-ratchet, fix/441-fapi-signing, fix/443-fapi2-exercise merged); tagged v0.2.5.

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #436 (refresh revocation leaves access tokens valid, P2).
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
