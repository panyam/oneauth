---
name: feedback-mutation-restore-from-copy
description: When mutating a file to red-check a test, restore it from a saved copy, never with git checkout, since the file usually holds the PR's uncommitted change.
metadata:
  type: feedback
---

Mutation checks here edit a source file, run the tests, and put the file back. Put it back from a copy taken just before the mutation (`cp f /tmp/f.bak` … `cp /tmp/f.bak f`), or from the source string held in the script. Never `git checkout -- f`.

**Why:** during PR #487 a mutation run restored `localauth/helpers.go` with `git checkout`. The file held that PR's uncommitted change, so the restore would have thrown the change away; the permission check refused the command. Work under test is almost always uncommitted.

**How to apply:** in a mutation script, read the file into a variable first and write that back in a `finally`; in shell, copy to the scratchpad first. Check the mutated line is back (`grep -c`) before going on. Related: [[red-check-each-test-not-the-suite]].
