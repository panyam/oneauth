---
name: never-run-ci-is-untested
description: "A workflow that has never passed is broken in several ways at once. Dispatch it before patching one detail of it, and capture that run as the before. Lesson from the Keycloak workflow (PR 390)."
metadata:
  node_type: memory
  type: feedback
---

A CI workflow that has never run green carries every bug it was written with, not just the one you noticed. Before fixing a detail of it (an image pin, a flag), dispatch it as-is and read how it fails.

**Why:** PR 388 left "bump the Keycloak workflow's image pin from 26.0 to 26.6" as the one leftover. Reading the whole file showed the pin was the least of it: a `services:` container gets no command, so Keycloak printed its usage and exited before any test ran, and it also couldn't pass `--features=dpop`, probed the wrong health port, ran `go test` against a nested module from the root, and never started the RAR issuer. Dispatching it on main (run 38691212033) confirmed it died in "Initialize containers". A pin bump alone would have shipped a workflow that still never ran a test.

**How to apply:** When a ticket touches a workflow (or any harness) with no green baseline, dispatch it first and use that failure as the PR's before. Prefer making CI call the same make target used locally over describing the setup twice in YAML, and trigger it on relevant PRs so it doesn't drift unrun again. Related: [[unrendered-is-unvalidated]].
