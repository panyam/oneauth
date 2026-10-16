# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. No active mission (`queue.sh` reports 0 active).
- This run: dropped test/88-interop-coverage (PR #398 merged) and ci/bump-zap-baseline (PR #399 merged); tagged v0.1.42.

## Across threads

- #88 is worked one audit area at a time; DPoP is done (`docs/SECURITY_AUDIT.md`). The first ZAP scan (PR #399's run) raised CSP `unsafe-inline`, missing SRI on the Tailwind CDN script, and a cookie without `HttpOnly`, which belong to #88's "Security headers" / session items when that area is walked.
- #395 holds the DPoP and refresh leftovers. Item 4 (SDK auto-refresh on the legacy endpoint, no client secret) also blocks confidential clients from auto-refreshing.
