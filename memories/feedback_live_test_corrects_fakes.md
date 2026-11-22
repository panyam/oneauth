---
name: feedback_live_test_corrects_fakes
description: A fake written from docs agrees with our code on every guess; one live run against the real service is what corrects it
metadata:
  type: feedback
---

A fake server written from the provider's docs encodes our own reading of those docs, so tests against it pass even where both are wrong. The first real-GitHub run of `make testgh` (PR #471) found three behaviours `githubtest` had wrong: unknown App ID is 404 not 401, a refresh kills the old access token, a second revoke is 404 not 422.

**Why:** the fake and the code under test were written by the same reader from the same docs, so they share every misreading. Only the real service breaks the tie. Same lesson as [[feedback_reference_comparison]], applied to fakes instead of our own server.

**How to apply:** when shipping a fake for an external service, also ship an env-gated live test that exercises the same paths, run it once before merging, and turn each difference into a fake fix plus a unit test that fails against the old fake. Log (don't assert) behaviours the docs don't state, then pin them once seen.

Second case, the `oauth2/oidc` device flow (PR 545): the fake issuer's `/device` accepted a request with no client secret, and so did the code under test, since `x/oauth2`'s `DeviceAuth` sends only `client_id`. Keycloak refused it with `unauthorized_client`. The fake now checks credentials at `/device`.
