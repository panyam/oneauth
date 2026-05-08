# Memory Index

- [feedback_god_interface.md](feedback_god_interface.md) — Avoid god interfaces; decompose by concern. Lesson from kid/KeyStore refactor where 3 workarounds piled up before decomposing.
- [feedback_subpackage_refactor.md](feedback_subpackage_refactor.md) — Lessons from large subpackage reorganization: regex scripts unreliable for Go type prefixing, use git mv for history, work in chunks, export struct fields when moving cross-package.
- [feedback_pr_docs.md](feedback_pr_docs.md) — Always update docs as part of every PR commit, not as afterthought. Close GitHub issue, update SUMMARY, ROADMAP, guide docs, subpackage SUMMARYs.
- [feedback_test_file_organization.md](feedback_test_file_organization.md) — Keep new test groups in separate _test.go files to prevent bloat in existing test files.
- [feedback_review_cadences.md](feedback_review_cadences.md) — Prefer ad-hoc `make X-report` targets over cron/calendar review cadences; advisory metadata (e.g., `expires:`) shouldn't gate.
- [feedback_stacked_branches_in_worktrees.md](feedback_stacked_branches_in_worktrees.md) — When local main is held by another worktree, cut new feature branches from `origin/main` directly. Don't try to `git checkout main`.
- [feedback_explicit_opt_in_for_dev_hacks.md](feedback_explicit_opt_in_for_dev_hacks.md) — Gate dev/test-only conveniences behind explicit opt-in flags; never make them silent fallbacks. Production misconfiguration should fail loudly.
