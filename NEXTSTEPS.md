# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: #489, every applicable external conformance suite (OIDF plans, the MCP conformance framework, OAuch), run from `make conformance`, reported on the docsite and linked from the README. 0/10 tickets; next ready #490 (`conformance/` with a suite registry, mcpkit's layout, orchestration only) and #491 (the 81-plan OIDF applicability table). The exercise doesn't exist until #490. JARM (#409) is parked, next ready #410.
- No open threads. Last release v0.3.7; seven merges since, so a release is due (see Across threads).
- This run: closed mission #477 (PRs #482, #483, #484, #487, #488) and started #489 with tickets #490 to #498; moved #243 onto it.

## Across threads

- The next release notes must call out two behaviour changes from PR #488: ID tokens no longer carry scope claims unless asked for by name (OIDC Core §5.4), and an `APIMiddleware` without DPoP refuses DPoP-bound tokens (#486). PR #484 adds a `consents` table and PR #487 two `authorization_codes` columns through GORM `AutoMigrate`.
- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #451 (subject-wide revocation should blacklist access tokens too, P3, waiting).
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
