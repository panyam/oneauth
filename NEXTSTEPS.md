# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No mission is active. JARM (#409) is closed, and #543 (uncategorised later work) is at 2/3 with #553 next. The next pick goes through `retriage`.
- No open threads on main. PRs 561 (issues 554, 555) and 562 (issue 558) merged after v0.3.19. #563 waits on them: agni and goapplib need a release that carries 561.
- This run: dropped feat/554-555-oauth2-pushdowns and feat/558-ps256-interop (both merged), and removed their worktrees.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
- `realm.json` changed in PRs 545, 547 and 548 (`test-jarm`). The shared Keycloak on :8180 still has the old realm, and the `oauth2/oidc` interop tests, `make exercise-jarm` and the `jarm` conformance suite fail on it. Run `make downkcl` before `make testkcl`.
