# Memory Index

- [feedback_god_interface.md](feedback_god_interface.md) — Avoid god interfaces; decompose by concern. Lesson from kid/KeyStore refactor where 3 workarounds piled up before decomposing.
- [feedback_subpackage_refactor.md](feedback_subpackage_refactor.md) — Lessons from large subpackage reorganization: regex scripts unreliable for Go type prefixing, use git mv for history, work in chunks, export struct fields when moving cross-package.
- [feedback_pr_docs.md](feedback_pr_docs.md) — Always update docs as part of every PR commit, not as afterthought. Close GitHub issue, update SUMMARY, ROADMAP, guide docs, subpackage SUMMARYs.
- [feedback_review_cadences.md](feedback_review_cadences.md) — Prefer ad-hoc `make X-report` targets over cron/calendar review cadences; advisory metadata (e.g., `expires:`) shouldn't gate.
- [feedback_explicit_opt_in_for_dev_hacks.md](feedback_explicit_opt_in_for_dev_hacks.md) — Gate dev/test-only conveniences behind explicit opt-in flags; never make them silent fallbacks. Production misconfiguration should fail loudly.
- [feedback_spec_inheritance.md](feedback_spec_inheritance.md) — When an RFC inherits comparison semantics from another RFC, look at the inherited spec's primitive — don't guess from the data type. Lesson from `ValidateIss` (#246, URL→JWT byte-equal).
