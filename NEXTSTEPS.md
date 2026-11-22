# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- Active mission: JARM (#409), at 1/4 tickets. Next ready is #411, in progress on feat/411-jarm-as (its thread lives on that branch). The exercise last ran at f23e38e, after PR 548.
- No open threads on main. v0.3.17 shipped PRs 547, 548 and 550. PR 550 (issue 549, off-mission) adds `core.APIKeyAdmin` for agni, which can now bump to v0.3.17 and drop its store readers (panyam/agni#1822).
- This run: feat/549-apikey-admin merged and was deleted.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- OAuch runs by hand (`docs/conformance/oauch.md`). Rerun it after a change to security headers or the authorization pages, and update the `oauch` entry in `conformance/suites.yaml`.
- `realm.json` changed in PRs 545, 547 and 548. A Keycloak container started before them has the old realm, and the `oauth2/oidc` interop tests and `make exercise-jarm` fail on it. Run `make downkcl` before `make testkcl`.
