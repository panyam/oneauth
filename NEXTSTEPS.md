# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No mission is active, and #543 has nothing ready. The next pick goes through `retriage`.
- No open threads on main. v0.3.24 (2026-11-27) is the latest tag, with #577 (`stores/gae` `WithSchemaRegistry`). #578 (`WithNumericUserKeys`) is merged but unreleased. Next: release v0.3.25. panyam/notation needs both to upgrade its pre-oneauth auth records online.
- #579 tracks the Windows-only flake in the FS store's admin contract tests, which hit #577 and #578.
- This run: #578 merged. Dropped the v0.3.20 and v0.3.21 lines, since v0.3.22 to v0.3.24 are out.

## Across threads

- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
