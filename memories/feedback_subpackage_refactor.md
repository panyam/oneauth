---
name: feedback_subpackage_refactor
description: Lessons from the large subpackage reorganization — regex scripts unreliable for Go, type aliases rejected, git mv preserves history
type: feedback
---

When doing large Go refactors (moving types across packages):
- Regex-based Python scripts for prefixing types are unreliable — they can't distinguish struct field names from type references. Manual editing or Go-aware tooling is needed.
- Don't use type aliases as a migration bridge — the user prefers direct migration even if it means more changes.
- Use `git mv` for file moves to preserve git blame history. Only use plain create for files that are splits/merges of multiple sources.
- Work in chunks to avoid context overload — write a plan file, process one package at a time.
- `BasicUser` fields needed to be exported (`ID`, `ProfileData` instead of `id`, `profile`) when moving to a separate package.

**Why:** Regex scripts over-matched, prefixing struct field names and string literals. Type aliases were rejected as unnecessary complexity.
**How to apply:** For future Go refactors, prefer subagents per-package with explicit build verification, or use `goimports`/`gopls rename` when available.
