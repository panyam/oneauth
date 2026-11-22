# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: JARM (#409), at 0/4 tickets. Next ready is #410, which makes `make exercise-jarm` runnable. Its exercise hasn't run yet.
- No open threads. Release v0.3.16 carries `TrustedProxies.IsHTTPS` (PR #544, issue 541) and `oauth2/oidc` (PR #545, issue 542). Both were off-mission pushdowns for agni issues 1810 and 1811.
- This run: no threads to drop. feat/541-is-https and feat/542-oidc-signin merged and were deleted.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
- A Keycloak container started before v0.3.16 has the old realm, and the `oauth2/oidc` interop tests fail on it with `invalid_scope`. Run `make downkcl` before `make testkcl`.
