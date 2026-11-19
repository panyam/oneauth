# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No active mission. #477 closed: the OIDF Basic OP plan runs in `make testoidf` with 28 of 35 modules passing and none failing. Next mission is a `/retriage` pick; the user wants more conformance suites (the OIDF Config, Dynamic, Form Post and logout plans first, then a survey of what else exists). JARM (#409) is parked, next ready #410.
- No open threads. Last release v0.3.7; seven merges since, so a release is due (see Across threads).
- This run: closed mission #477 after PRs #482, #483, #484, #487, #488; dropped the #453 line (closed, leftovers in #485).

## Across threads

- The next release notes must call out two behaviour changes from PR #488: ID tokens no longer carry scope claims unless asked for by name (OIDC Core §5.4), and an `APIMiddleware` without DPoP refuses DPoP-bound tokens (#486). PR #484 adds a `consents` table and PR #487 two `authorization_codes` columns through GORM `AutoMigrate`.
- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #451 (subject-wide revocation should blacklist access tokens too, P3, waiting).
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
