# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: #489, every applicable external conformance suite run from `make conformance`. 17/17 tickets closed. The report's Known gaps section lists 24 entries, 6 open and 18 accepted. The mission closes when its owner reads that section and agrees nothing is papered over. JARM (#409) is parked, next ready #410.
- No open threads. Release v0.3.14 carries CIMD (PR #536, issue 532), `mcp-auth-as` (PR #533), the known-gaps classes (PR #535), `make up-all` (PRs #530, #531) and Go 1.27.4 (PR #534).
- This run: dropped feat/532-cimd (PR #536 merged).

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
