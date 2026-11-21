# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: #489, every applicable external conformance suite run from `make conformance`. 17/17 tickets closed. PR #535 gave every `known-gaps.yaml` entry an `open` or `accepted` class, and the report now has a Known gaps section (7 open, 18 accepted). The mission closes when its owner reads that section and agrees nothing is papered over. The MCP suites ran on main at `eb5e420`. The last full `make conformance` ran for PR #530 at `aecf2e6`. JARM (#409) is parked, next ready #410.
- feat/532-cimd — #532 (server-side CIMD) — in progress in `../oneauth-532`; next: open its PR after merging main, so its known-gaps edit uses the class field.
- This run: dropped feat/489-gap-classes (PR #535 merged).

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
