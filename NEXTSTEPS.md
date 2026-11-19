# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: #477, an OIDC relying party passes the OIDF Basic OP plan against oneauth. 0/2 tickets; next ready #290 (add `make exercise-oidcc`, mirroring `make exercise-fapi2`). Its exercise has never run, and #290 is what makes it runnable. JARM (#409) is parked, next ready #410.
- No open threads. Last release v0.3.7 (first cut with `make release`).
- This run: retriage. 72 open issues became 55. 16 Auth0 product-feature issues and #81 / #125 closed (the gap analysis keeps the rows), spec tickets filed under #163, provider login under #119, #115 parked.

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #451 (subject-wide revocation should blacklist access tokens too, P3, waiting).
- OIDC Core shipped in #454, and SDK ID token checks in #455. #453 (now P2 on mission #477) keeps the server-side items plus two SDK follow-ups in its comments (refresh drops the ID token, no CLI flag).
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
