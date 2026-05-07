---
name: feedback_review_cadences
description: For recurring audits/reviews, prefer ad-hoc reports + checked-in artifacts over cron-based or calendar-based cadences.
type: feedback
---

When designing a periodic review mechanism (suppression review, gap audit, dependency check, anything "we should look at this every N days"), default to **ad-hoc with a checked-in report**, not a cron or calendar trigger.

Pattern: a `make <something>-report` target writes a Markdown summary to `test-reports/`. Run when a human wants to look. The report itself is the artifact.

**Why:** Validated during the conformance-testing PR. I initially proposed quarterly suppression review (per the strategy doc); user pushed back: "i dont need a quarterly review yet — it should be weekly i think given our cadence — or even better just adhoc (like our `make testall` in mcpkit which runs *everything* and creates reports — wdyt?)". The reasoning that landed: time-based cadences degenerate into mechanical "bump expires by 90 days" PRs with no real review; ad-hoc means the review happens when there's a question to answer, and the strongest staleness signal is usually the gating mechanism itself (e.g., the ratchet catches "gap silently shipped" without any review).

**How to apply:**
- Default to `make X-report` over GH Actions cron or scheduled jobs.
- Keep advisory metadata (e.g., `expires:` dates) as report-sort hints, not as enforced gates — enforcement creates fire drills.
- The `test-reports/` directory in this repo is checked-in-explicitly territory; reports go there.
- If the gating mechanism (CI ratchet, lint, etc.) already catches the most important staleness case, say so explicitly when proposing the review — it's often enough on its own.
- This is a decision point worth surfacing rather than picking silently. The user wants to weigh in on cadence questions.
