# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: #489, every applicable external conformance suite run from `make conformance`. 17/17 tickets closed, after PR #533 added `mcp-auth-as` (issue 496). Its last done-when item is a person's review of the report, so closing it is the owner's call. The MCP suites ran on main at `eb5e420`. The last full `make conformance` ran for PR #530 at `aecf2e6`, where Authlete (info) failed 4 tests on `invalid_client` because `AUTHLETE_CLIENTID` isn't registered in the service. JARM (#409) is parked, next ready #410.
- Next: #532 (server-side CIMD), the one gap `mcp-auth-as` found, recorded as an expected warning.
- No open threads. This run: no branch threads to merge; refreshed the mission line after PR #533.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
