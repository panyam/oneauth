# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads and no active mission. #98 (OIDF FAPI 2.0) closed 2026-10-18 after its last run @ 022cabb (41 of 46 passed, 4 REVIEW, 1 RS256 skip pending #330); `make testoidf` guards it. JARM (#409) is parked, next ready #410.
- This run: no branch threads to prune (feat/339-oidc-core merged as PR #454, off-mission). The FAPI 2.0 plan now runs as `openid_connect` (52 modules: 45 pass, 4 REVIEW, 2 skips, 1 expected warning).

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #451 (subject-wide revocation should blacklist access tokens too, P3, waiting).
- OIDC Core shipped in #454; what it left out is #453 (waiting). #290 (OIDF Basic / Dynamic plans), #340 and #341 are no longer blocked on it.
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
