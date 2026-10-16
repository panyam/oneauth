# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- test/88-interop-coverage — PR #398 (refs #88) — next: review and merge, then tag v0.1.42
- No active mission (`queue.sh` reports 0 active).
- This run: v0.1.41 tagged with #396 (DPoP audit) and #397 (refresh client check); both worktrees removed.

## Across threads

- #88 is worked one audit area at a time; DPoP is done (`docs/SECURITY_AUDIT.md`). The next area is unpicked.
- #395 holds the DPoP and refresh leftovers. Item 4 (SDK auto-refresh on the legacy endpoint, no client secret) now also blocks confidential clients from auto-refreshing.

## test/88-interop-coverage

- **Last touched**: 2026-10-15 (sri-mac:~/newstack/oneauth/oneauth-88-interop)
- **Ticket**: #88 (PR #398)
- **Why**: e2e and Keycloak comparison coverage for #396 / #397, plus the three bugs it found.
- **Where it stopped**: PR open, `make test`, `make e2e`, `make testkcl` pass locally; CI running.
- **Next action**: after merge, add release notes for 0.1.42 (status 400 for refresh `invalid_grant`, `invalid_client` for a missing `client_id`, the `LoginWithBrowser` DPoP fix) and tag.
- **Open questions**: none.
