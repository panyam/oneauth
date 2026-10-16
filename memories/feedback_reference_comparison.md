---
name: reference-comparison-finds-shared-misreadings
description: "Tests where both sides are ours can't catch a shared misreading of a spec; send the same request to a reference server and pin both answers. Lesson from the issue 88 Keycloak comparisons."
metadata:
  node_type: memory
  type: feedback
---

Unit tests that drive our client against our server pass whenever the two agree, including when they agree on something wrong. Sending the identical request to a reference implementation and asserting on both answers is what catches that.

**Why:** After the DPoP audit (PR 396) and the refresh client check (PR 397) both shipped green, a side-by-side suite against Keycloak plus one full-stack e2e found three bugs in an afternoon: the refresh grant sent `invalid_grant` with 401 (RFC 6749 §5.2 says 400), a missing `client_id` got `invalid_grant` instead of `invalid_client`, and `LoginWithBrowser` with a DPoP key could never log in, because it sent `dpop_jkt` on the authorize URL and then exchanged the code without a proof. Every piece of that last one had its own passing test. Nothing ran the authorize step and the exchange together with a key.

**How to apply:**
- For any wire-visible behavior, write the comparison as a table of cases with both servers' expected answers, and assert both. Where they differ on purpose, pin both and document why in `docs/SECURITY_AUDIT.md`, so a change on either side shows up.
- Don't treat the reference as authoritative. Keycloak uses `invalid_request` where RFC 9449 names `invalid_dpop_proof`, and refuses `htu` spellings §4.3 says to accept. Check the RFC before aligning.
- When a feature puts something on one request that a later request must honor (`dpop_jkt` then the exchange, `code_challenge` then the verifier), test the whole flow end to end, not each call.

Related: [[feedback_red_check_each_test]], [[feedback_capture_the_artifact]].
