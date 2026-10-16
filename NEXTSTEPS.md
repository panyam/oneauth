# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. No active mission (`queue.sh` reports 0 active).
- This run: dropped the five issue 88 HTTP-surface branches (PRs #403 to #407 merged); tagged v0.1.44.

## Across threads

- #88 is worked one audit area at a time; DPoP and the HTTP surface (transport, sessions, admin) are done (`docs/SECURITY_AUDIT.md`). Left on #88: token security, key management, input validation, the rest of FAPI. HTTP-surface leftovers are #408.
- GAE store tests are deterministic now but still don't run in CI (they need an emulator service); no issue filed yet.
