# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. Retriage in progress: the FAPI 2.0 conformance mission (#98) becomes active once the docs/oauth refresh lands.
- This run: dropped feat/dpop-proof-with-nonce (PR #432 merged); tagged v0.2.0 (first GitHub release since v0.1.37) and v0.2.1.

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. The one open follow-up is #421 (retired keys in JWKS), waiting.
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
