---
name: Test file organization
description: Keep new test groups in separate _test.go files to prevent bloat in existing test files
type: feedback
---

New test groups should go in dedicated `_test.go` files (e.g., `client_nil_test.go`) rather than appending to existing test files.

**Why:** User prefers this to prevent test file bloat and keep test groups focused.

**How to apply:** When adding tests for a new feature/fix, create a new `<topic>_test.go` file in the same package instead of appending to the existing test file.
