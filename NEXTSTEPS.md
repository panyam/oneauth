# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: #489, every applicable external conformance suite run from `make conformance`. 5/10 tickets closed. Next ready #495 (MCP conformance framework against oneauth-server), then #497 (OAuch) and #498 (`make testoidf` in CI). The exercise (`make conformance`) last ran for PR #504 at `9dafd3b`. PRs #503, #506, #509 and #512 merged since, none on the mission. JARM (#409) is parked, next ready #410.
- No open threads. Last release v0.3.10 (the `oauth2` fixes for agni, PR #512).
- This run: dropped the v0.3.8 release-notes reminder (shipped); no threads to merge.

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #451 (subject-wide revocation should blacklist access tokens too, P3, waiting).
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
