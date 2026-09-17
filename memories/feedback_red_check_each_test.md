---
name: red-check-each-test-not-the-suite
description: "A test that stays green when you disable the feature is testing something weaker than its name claims. Red-check per test, and strengthen the ones that survive. Lesson from the DPoP client PR (#377, PR 379)."
metadata:
  node_type: memory
  type: feedback
---

Red-before-green is usually described as a property of a suite: break the production code, watch tests fail. The useful version is per test. Look at *which* tests fail, and treat any test that stays green as a finding about that test.

**Why:** Concrete case: PR 379 added `TestDPoPClient_SpendsTheBoundTokenAtAResourceServer`, which obtained a token with a DPoP key and spent it at a resource server. Disabling proof minting entirely left it green. The client then got a plain bearer token, and the resource server accepts bearer tokens too, so the request still returned 200. The test was named for the bound path and was in fact asserting "the happy path still works". The fix was to assert the token carries `cnf` before spending it, after which it fails red for the right reason.

The same session produced the sharper version of this: a flaky base64 tamper test that surfaced only because it failed during a red-check of an *unrelated* change (see [[feedback_encoding_layer_normalization]]).

**How to apply:**
- Disable one production behavior at a time and record which tests fail. Comparing that list against the test names is the check; "the suite went red" is not.
- A test that survives is usually asserting a precondition or a weaker property than its name claims. Strengthen it by asserting the thing that distinguishes the new path, not just its outcome.
- Watch for this shape specifically: a new stricter path layered over a permissive one that still works. The permissive fallback keeps the test green and hides the gap.
- A test that fails during a red-check of something unrelated is reporting a bug in itself. Investigate rather than re-running.
