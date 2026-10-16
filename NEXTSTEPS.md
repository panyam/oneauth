# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- fix/88-keys — #88 — next: commit the EncryptedKeyStorage fail-closed work, then KidStore encryption, key size, JWKS, `make audit`
- fix/codeql-warnings — CodeQL warnings — next: finish the cookie / workflow / redirect fixes and open the PR
- No active mission (`queue.sh`: 1 open, 0 active; JARM #409 is parked).
- This run: dropped fix/88-tokens-keys, fix/88-revocation, fix/codeql-errors (PRs #414 to #416 merged); tagged v0.1.45.

## Across threads

- #88 is worked one audit area at a time; DPoP, the HTTP surface and token security are done (`docs/SECURITY_AUDIT.md`). Left on #88: key management (fix/88-keys), input validation and RFC rows, the rest of FAPI. HTTP-surface leftovers are #408.
- GAE store tests are deterministic now but still don't run in CI (they need an emulator service); no issue filed yet.

## fix/88-keys

- **Last touched**: 2026-10-16 (mac:/Users/sri/newstack/oneauth/oneauth-88-keys)
- **Ticket**: #88, the "Key Management" walk (PR C of the tokens-and-keys slice)
- **Why**: stored keys must fail closed and be bound to their record.
- **Where it stopped**: uncommitted. `keys/encrypted.go` has the `oaenc1:` format with AAD, `ErrKeyDecrypt`, `AllowLegacyPlaintext` and `MigrateLegacy`; `keys/encrypted_failclosed_test.go` was red first and passes. Branch is based on the pre-merge revocation commit, so rebase onto main first.
- **Next action**: rebase onto origin/main, wire `AllowLegacyPlaintext` / `MigrateLegacy` into the reference server's `key_store` config, then KidStore retired-key encryption (GORM / GAE), RSA ≥ 2048 on load, JWKS hygiene, the RFC 7638 vector test, `make audit` via pinned `go run`, a `CleanExpired` sweeper.
- **Open questions**: whether v0 (unprefixed, no-AAD) ciphertext should stay readable by default (currently yes, since only the master key could have written it).

## fix/codeql-warnings

- **Last touched**: 2026-10-16 (mac:/Users/sri/newstack/oneauth/oneauth-cqw)
- **Ticket**: none; clears the 26 open warning-level CodeQL alerts.
- **Where it stopped**: branch cut, nothing edited yet. No sibling repo reads the `loggedInSubject` cookie from script, so it can become HttpOnly.
- **Next action**: Secure + HttpOnly on the oauth2 / federatedauth / demo-hostapp cookies (including delete cookies), `permissions: contents: read` on the workflows, then decide `LocalRedirect` (CodeQL doesn't see it as a sanitizer) and the OIDF harness's `InsecureSkipVerify`.
- **Open questions**: dismiss the OIDF harness alert as test-only, or pin the suite's certificate.
