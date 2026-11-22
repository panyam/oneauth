# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Mission JARM (#409) is at 4/4. `make exercise-jarm` works at a879075 on both targets, and the tampered run is refused. It closes once the user confirms the exercise output. Its follow-ups are #553 and #557, under the uncategorised mission #543. No other mission is active, so the next pick goes through `retriage`.
- No open threads on main. PRs 548, 551, 552 and 556 merged after v0.3.17, and a release is being cut next.
- This run: feat/410 to feat/413 merged; fix/537-vulncheck-tag's worktree removed (issue 537 was already closed).

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
- `realm.json` changed in PRs 545, 547 and 548 (`test-jarm`). The shared Keycloak on :8180 still has the old realm, and the `oauth2/oidc` interop tests, `make exercise-jarm` and the `jarm` conformance suite fail on it. Run `make downkcl` before `make testkcl`.
