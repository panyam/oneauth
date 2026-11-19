# Next steps

Where each line of work left off. Work items live in GitHub issues; this file points at them.
Maintained by /checkpoint: one thread per branch, pruned when the branch merges.

## At a glance

- feat/467-outbound-credentials — #467 (PR #469) — next: review, then point goapplib#153 at `outbound` types
- No active mission. #98 (OIDF FAPI 2.0) closed 2026-10-18 after its last run @ 022cabb (41 of 46 passed, 4 REVIEW, 1 RS256 skip pending #330); `make testoidf` guards it. JARM (#409) is parked, next ready #410.
- This run: added the feat/467 thread; no other open PRs, so no threads to prune. Root CLAUDE.md trimmed from 30.9k to 5.2k chars; gotchas moved to per-directory CLAUDE.md files.

## Across threads

- The issue 88 audit is closed; `docs/SECURITY_AUDIT.md` opens with its summary. Open follow-ups: #421 (retired keys in JWKS, waiting) and #451 (subject-wide revocation should blacklist access tokens too, P3, waiting).
- OIDC Core shipped in #454, and SDK ID token checks in #455. #453 (waiting) keeps the server-side items plus two SDK follow-ups in its comments (refresh drops the ID token, no CLI flag). #290 (OIDF Basic / Dynamic plans), #340 and #341 are no longer blocked on OIDC.
- Token-slice candidates not filed: real logout tokens / ID-JAGs at the middleware (e2e), GORM rotation under real Postgres concurrency, a test on the server's own `/api/revoke`, the SDK on 403.

## feat/467-outbound-credentials

- **Last touched**: 2026-11-18 (oneauth/oneauth-467 worktree)
- **Ticket**: #467 (PR #469); follow-ups in #468 (P3, waiting on goapplib#153)
- **Why**: outbound `oauth2.TokenSource`s (GitHub App installation, stored user tokens, static secrets) for goapplib's storage mounts.
- **Where it stopped**: PR open with the anchored Reviewer's guide and one self-comment on the `Expiry` shift. The checkpoint commit in the same PR trims CLAUDE.md.
- **Next action**: after review and merge, comment on panyam/goapplib#153 naming `outbound.GitHubAppInstallation`, `outbound.UserTokens` and `outbound/githubtest`, which the issue's "Done when" asks for.
- **Open questions**: whether goapplib runs more than one replica soon. If it does, #468's GORM `UserTokenStore` moves up, since the FS store's compare-and-swap holds within one process only.

