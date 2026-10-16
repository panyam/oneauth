# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. No active mission (`queue.sh`: 1 open, 0 active; JARM #409 is parked).
- This run: dropped fix/408-http-followups (PR #428 merged, #408 closed); tagged v0.1.55.

## Across threads

- #88 is worked one audit area at a time; DPoP, the HTTP surface and token security are done, and so is key management (`docs/SECURITY_AUDIT.md`). Input validation at the token endpoint is done too. `/authorize`, PAR, PKCE and the device flow are done too. Input validation is finished (token endpoint, authorize/PAR/PKCE/device, DCR, metadata, FS key collisions). FAPI 2.0 and #408 are done. Next on #88: the closing write-up in SECURITY_AUDIT.md (FAPI readiness summary, gap list with estimates, test-coverage table), then close #88. Retired-key JWKS publishing is #421.
- Token-slice follow-ups not filed, still candidates: real logout tokens / ID-JAGs at the middleware (e2e), revocation parity with Keycloak, GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- GAE store tests are deterministic now but still don't run in CI (they need an emulator service); no issue filed yet.
