---
name: feedback-verify-merge-before-tagging
description: Post-merge steps (worktree removal, checkpoint, tag) run only after gh reports the PR MERGED; a command chain that prints the state must also stop on it.
metadata:
  type: feedback
---

Before any post-merge step (removing the worktree, writing release notes, `make tag` / `make pushtag`), check `gh pr view N --json state` and stop unless it says `MERGED`. A chain like `gh pr view ... --jq .state && git pull && ... && make pushtag` prints `OPEN` and keeps going, because `gh pr view` succeeded.

**Why:** in the issue 88 run, "merged" arrived for #427 before GitHub showed it merged. The chain pushed a checkpoint describing #427 and eleven `v0.1.53` tags at a main that didn't contain it. Pushed tags can't be safely moved (the Go module proxy may have cached them), so v0.1.53 had to stay as a docs-only release with corrected notes, and the real release became v0.1.54.

**How to apply:** gate the chain on the state, e.g. `[ "$(gh pr view N --json state --jq .state)" = MERGED ] || exit 1`, and check `git merge-base --is-ancestor <pr-head> HEAD` before tagging. If the user says "merged" and GitHub disagrees, say so and wait. Related: [[capture-the-artifact-not-the-substring]] (check the real state, not the message about it).
