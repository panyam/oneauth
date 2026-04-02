# Memory Index

- [feedback_god_interface.md](feedback_god_interface.md) — Avoid god interfaces; decompose by concern. Lesson from kid/KeyStore refactor where 3 workarounds piled up before decomposing.
- [feedback_subpackage_refactor.md](feedback_subpackage_refactor.md) — Lessons from large subpackage reorganization: regex scripts unreliable for Go type prefixing, use git mv for history, work in chunks, export struct fields when moving cross-package.
- [feedback_pr_docs.md](feedback_pr_docs.md) — Always update docs as part of every PR commit, not as afterthought. Check NEXTSTEPS, SUMMARY, guide docs, subpackage SUMMARYs.
- [project_e2e_refactor.md](project_e2e_refactor.md) — Plan to replace Python subprocess integration tests with Go in-process e2e tests using httptest.NewServer. Extract NewHandler(config) from cmd/*/main.go.
