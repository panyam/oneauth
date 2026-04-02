---
name: feedback_pr_docs
description: Always update docs as part of every PR — don't skip the doc step even when excited about shipping code
type: feedback
---

Every PR must include doc updates as specified in the /start_pr skill checklist. Don't commit code and then update docs as an afterthought — do it in the same commit.

**Why:** The user caught that #27 (PKCE) was committed without updating NEXTSTEPS.md, SUMMARY.md, BROWSER_AUTH.md, or adding an oauth2/SUMMARY.md. The /start_pr skill explicitly requires this.

**How to apply:** Before committing a PR, check:
1. NEXTSTEPS.md — mark the issue as completed
2. SUMMARY.md — add version entry
3. Relevant guide docs (BROWSER_AUTH, API_AUTH, etc.) — mention new features
4. Subpackage SUMMARY.md — update if new types/functions added
5. CLAUDE.md — update if conventions or imports changed
