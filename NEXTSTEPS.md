# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: #489, every applicable external conformance suite run from `make conformance`. 16/17 tickets closed. Nothing ready: #496 waits on the upstream MCP authorization-server suite. The last full `make conformance` ran for PR #530 at `aecf2e6`: 17 gating suites pass, and Authlete (info) fails 4 tests on `invalid_client` because `AUTHLETE_CLIENTID` isn't registered in the service. JARM (#409) is parked, next ready #410.
- No open threads. Releases v0.3.12 and v0.3.13 are cut; PRs #530 and #531 (`make up-all` over `docker-compose.yml`, issue 243) merged after v0.3.13.
- This run: no branch threads to merge; refreshed the mission line.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
