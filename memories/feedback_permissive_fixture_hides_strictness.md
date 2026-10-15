---
name: permissive-fixture-hides-strictness
description: "A shared test fixture that skips a validation can't catch bugs in that validation, however many tests use it. Check what the fixture turns off before trusting it for a strictness bug. Lesson from issue 387 / 389."
metadata:
  node_type: memory
  type: feedback
---

When a bug is about how strictly a server checks something, first check whether the shared fixture checks it at all.

**Why:** Issue 387 was a client sending a `redirect_uri` that didn't match what it registered, against a server matching exactly. Every headless e2e test passed throughout, because `tests/e2e/authserver_test.go` mounts `/authorize` on a `OneAuth` with no `AppStore`, which turns redirect validation off and accepts any redirect. Building a server with the AppStore DCR writes into (`tests/e2e/loopback_listener_test.go`) showed oneauth's own AS was exactly as strict as the third-party server that tripped mcpkit, even though the registrar's doc said loopback ports were unconstrained. That became issue 389.

**How to apply:** For a validation bug (redirects, audiences, scopes, client auth), read the fixture's config for the nil/disabled knob before adding a test to it. If the shared fixture has it off, write a focused fixture with it on rather than flipping it for every test. Related: [[red-check-each-test-not-the-suite]].
