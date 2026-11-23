# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No mission is active, and #543 has nothing ready. The next pick goes through `retriage`.
- No open threads on main. v0.3.20 carries PRs 561, 562, 564 and 565. Its release fires the trigger on #563, so goapplib and agni can now move to `GitHubHostsFor` and `Resolve`.
- v0.3.21 carries PRs 568 (`oauth2/oidc/oidctest`, plus the device-flow `AuthStyle` fix) and 569 (automated OAuch run). agni#1811 can now move to `oidctest`.
- This run: released v0.3.21.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
