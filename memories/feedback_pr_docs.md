---
name: feedback_pr_docs
description: Always update docs as part of every PR — don't skip the doc step even when excited about shipping code
type: feedback
---

Every PR must include doc updates as specified in the /start_pr skill checklist. Don't commit code and then update docs as an afterthought — do it in the same commit.

**Why:** The user caught that #27 (PKCE) was committed without updating tracking docs (then NEXTSTEPS.md, since deleted), SUMMARY.md, BROWSER_AUTH.md, or adding an oauth2/SUMMARY.md. The /start_pr skill explicitly requires this. NEXTSTEPS.md was retired 2026-05-06 in favor of GitHub issues + ROADMAP.md + #163 (Authlete tracker) — close the relevant GitHub issue instead.

**How to apply:** Before committing a PR, check:
1. GitHub issue — close it (or mark progress on the meta-tracker like #163)
2. SUMMARY.md — add version entry
3. ROADMAP.md — update if the PR shifts the standards/interop plan
4. Relevant guide docs (BROWSER_AUTH, API_AUTH, etc.) — mention new features
5. Subpackage SUMMARY.md — update if new types/functions added
6. CLAUDE.md — update if conventions or imports changed
