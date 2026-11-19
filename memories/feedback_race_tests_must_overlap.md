---
name: feedback_race_tests_must_overlap
description: A concurrency test that never makes its calls overlap passes while the code is broken; release them together after a warm-up
metadata:
  type: feedback
---

A race test is evidence only if its calls actually overlap. The device store's approve/deny race test (PR #474) passed 300 runs on Postgres while GORM's approve was a read-then-Save that let a late approval overwrite a denial. A start barrier alone didn't help. Each goroutine opened a fresh pool connection on its first query, and connection setup staggered the calls. Once each goroutine made one read before the barrier, the bug showed in 150 of 300 runs.

**Why:** a race test that stays green proves nothing unless something shows the racers met. Green after 300 runs looked like strong evidence and was none. Same family as [[feedback_red_check_each_test]]: a test has to fail without the fix, not just pass with it.

**How to apply:** in any concurrency test against a pooled backend, have each goroutine do a cheap read, wait on a barrier, then race. Then check the test goes red by breaking the atomicity (drop the WHERE clause, the lock or the transaction) and running it against the real backend, not only sqlite or memory.
