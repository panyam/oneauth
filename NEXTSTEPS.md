# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. No active mission (`queue.sh` reports 0 active).
- This run: dropped the three issue 395 branches (PRs #400 to #402 merged, #395 closed); tagged v0.1.43.

## Across threads

- #88 is worked one audit area at a time; DPoP is done (`docs/SECURITY_AUDIT.md`). The first ZAP scan (PR #399's run) raised CSP `unsafe-inline`, missing SRI on the Tailwind CDN script, and a cookie without `HttpOnly`, which belong to #88's "Security headers" / session items when that area is walked.
- GAE store tests are deterministic now but still don't run in CI (they need an emulator service); no issue filed yet.
