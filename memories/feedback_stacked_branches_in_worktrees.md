---
name: feedback_stacked_branches_in_worktrees
description: When local main is held by another worktree, cut new feature branches from origin/main directly instead of trying to git checkout main locally.
type: feedback
---

This repo is a bare repo at `/Users/dzshrh/newstack/oneauth` with multiple worktrees: `main/` (where most work happens), `conformance/`, `rfc-extensions/`. Worktrees can each hold one branch; `main` is often checked out in a sibling worktree (e.g., `conformance/`) for parallel work.

**The trap:** doing `git checkout main` from a feature branch in `main/` fails with "fatal: 'main' is already used by worktree at ...". Same issue with `git branch -f main origin/main` to fast-forward — branch is locked elsewhere. This bit me mid-flight several times when I tried to "switch back to main and cut a fresh branch".

**The pattern that works:**
- Cut new feature branches directly from `origin/main`: `git checkout -b feat/issue-N origin/main`. This switches you off the current branch and creates the new one tracking origin/main, no `git checkout main` needed.
- Sync via `git fetch origin --prune` to pull in remote-deleted branches and refresh `origin/main`. The local `main` ref staying behind is fine — `origin/main` is what you cut from.
- Delete the previous (merged) feature branch with `git branch -D <branch>` after cutting the new one — you can't delete the branch you're currently on.

**Why this matters:** when an in-flight session involves 3-5 stacked PRs in a row, each merging and triggering "cut next from updated main", the local `main` ref isn't the source of truth — `origin/main` is. Treating it that way makes the cadence reliable.

**Don't:** discard local changes via `git checkout` to recover. If a `checkout -b` fails partway and leaves stray modifications, `git stash push --include-untracked -m "<descriptive name>"` is the safe move — the user can recover the stash later in whichever worktree the changes belong to. (This bit us in the #166 → #167 transition where in-progress RFC-9207 work from another worktree leaked into the main worktree's index.)
