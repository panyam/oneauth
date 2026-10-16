# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- No open threads. No active mission (`queue.sh`: 1 open, 0 active; JARM #409 is parked).
- fix/408-http-followups — #408 — next: finish DCR initial access tokens and CSRF binding, then open the PR
- feat/88-server-fapi — #88 — PR #427 open: reference-server PAR + fapi2. Tag v0.1.54 when it merges (notes held in the 0.1.53 correction).
- This run: v0.1.53 was tagged early (docs only, code = v0.1.52); notes corrected.

## Across threads

- #88 is worked one audit area at a time; DPoP, the HTTP surface and token security are done, and so is key management (`docs/SECURITY_AUDIT.md`). Input validation at the token endpoint is done too. `/authorize`, PAR, PKCE and the device flow are done too. Input validation is finished (token endpoint, authorize/PAR/PKCE/device, DCR, metadata, FS key collisions). FAPI 2.0: the library `FAPI2` is merged; the reference server's `fapi2` is PR #427. Next: #408 (in progress), then the closing write-up in SECURITY_AUDIT.md, then close #88 and #408. Retired-key JWKS publishing is #421. HTTP-surface leftovers are #408.
- Token-slice follow-ups not filed, still candidates: real logout tokens / ID-JAGs at the middleware (e2e), revocation parity with Keycloak, GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.
- GAE store tests are deterministic now but still don't run in CI (they need an emulator service); no issue filed yet.
