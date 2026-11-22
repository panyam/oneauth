# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: JARM (#409), at 0/4 tickets. Next ready is #410, which makes `make exercise-jarm` runnable. Its exercise hasn't run yet.
- No open threads. PR 547 (issue 546, off-mission) merged after v0.3.16 and is unreleased: GitHub/Google callbacks use `VerifyState`, and `oidc.Provider.LogoutURL` adds RP-initiated logout.
- This run: feat/546-oauth2-logout merged and was deleted.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
- `realm.json` changed in PRs 545 and 547. A Keycloak container started before PR 547 has the old realm, and the `oauth2/oidc` interop tests fail on it. Run `make downkcl` before `make testkcl`.
