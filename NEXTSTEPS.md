# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: JARM (#409), at 0/4 tickets. Next ready is #410, which makes `make exercise-jarm` runnable. Mission #489 (conformance) closed on 2026-11-21 with every suite passing.
- No open threads. Release v0.3.14 carries CIMD (PR #536, issue 532), `mcp-auth-as` (PR #533), the known-gaps classes (PR #535), `make up-all` (PRs #530, #531) and Go 1.27.4 (PR #534).
- This run: dropped feat/532-cimd (PR #536 merged).

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
