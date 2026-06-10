---
name: feedback_test_fixtures_as_product_features
description: When a test hand-rolls mux/server wiring, ask whether that wiring belongs in the library — production deployments shouldn't have to re-derive it.
type: feedback
---

When writing an e2e or integration test, watch for the signal: "I'm hand-wiring routes / handlers / config that a real deployment will also need." If yes, the right shape is usually:

1. A small library helper (e.g. `apiauth.MountX(mux, cfg)`) that owns route placement and handler construction.
2. The test fixture calls the helper with shim integration points (test-header subject source, fixed CSRF token, no-op middleware).
3. The reference server (`cmd/oneauth-server`) calls the same helper with real integration points (cookie-based subject, `httpauth.CSRFToken`, `csrf.Protect`).

That way the test exercises the same wire-up production deployments use, and the helper gets validated by two genuinely different callers.

**Why:** The original PR 286 e2e test hand-rolled the RFC 8628 mux because `cmd/oneauth-server` had zero device-flow wiring. The user pushed back: "are we building what could be product features as test fixtures?" The fold-in extracted `apiauth.MountDeviceFlow` + `DeviceFlowMountConfig`, refactored the e2e to call it, and added the `device_flow:` yaml block to the reference server — three pieces that validate each other.

**How to apply:**
- Before merging an e2e PR, scan the fixture for `mux.Handle` / route-wiring blocks. Each one is a candidate for extraction.
- Precedents: `apiauth.MountASMetadata` (RFC 8414), `apiauth.MountDeviceFlow` (RFC 8628).
- One-caller helpers risk being API-designed for that one consumer. Two real callers (test + reference server) is the validation bar.
- Asymmetric middleware (browser routes wrapped with CSRF, machine routes not) is a non-obvious detail worth pinning with a unit test so future refactors that wrap everything uniformly fail loudly.

Related: [[feedback_pr_docs]] (always update docs as part of the PR), [[feedback_god_interface]] (decompose by concern).
