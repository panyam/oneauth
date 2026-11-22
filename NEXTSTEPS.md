# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No mission is active, and #543 has nothing ready. The next pick goes through `retriage`.
- No open threads on main. v0.3.20 carries PRs 561, 562, 564 and 565. Its release fires the trigger on #563, so goapplib and agni can now move to `GitHubHostsFor` and `Resolve`.
- This run: dropped fix/553-unpublished-module-bumps and feat/563-id-token-jti (both merged), and removed their worktrees.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
- `realm.json` changed in PRs 545, 547 and 548 (`test-jarm`). The shared Keycloak on :8180 still has the old realm, and the `oauth2/oidc` interop tests, `make exercise-jarm` and the `jarm` conformance suite fail on it. Run `make downkcl` before `make testkcl`.
