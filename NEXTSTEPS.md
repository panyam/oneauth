# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: #489, every applicable external conformance suite run from `make conformance`. 9/13 tickets closed. Next ready #519 (OAuch's gaps: repeated parameters, client credentials in the URI, a redirect fragment), then #521 (MCP auth follow-ups) and #243. #496 waits on the upstream MCP AS suite. The OIDF plans now also run nightly in CI (`oidf-conformance.yml`); the run dispatched on main after PR #520 is 44665445346. The last full `make conformance` was for PR #515 at `0ddf191`, and PRs #517, #518, #520 and #522 merged since. JARM (#409) is parked, next ready #410.
- No open threads. Release v0.3.11 is cut after this checkpoint (PRs #509 to #522).
- This run: dropped the issue 88 follow-ups line (#421 and #451 closed); no branch threads to merge.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
