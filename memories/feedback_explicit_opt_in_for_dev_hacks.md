---
name: feedback_explicit_opt_in_for_dev_hacks
description: When a feature has both a production-correct path and a dev/test-only convenience, gate the convenience behind an explicit opt-in flag — never make it the silent fallback.
type: feedback
---

When designing config knobs that have a "production correct" form and a "test/dev convenient" shortcut (e.g., persistent signing key vs. ephemeral keypair, real DB vs. in-memory store, real secret vs. auto-generated), **gate the shortcut behind an explicit opt-in flag**. Don't make it the silent fallback when the production field is unset.

**Why:** validated during the #184 / #194 discussion. I initially proposed: "if `jwt.signing_alg=RS256` and no `private_key_path` is set, auto-generate a fresh keypair on startup." User pushed back on this being a "POC dumping ground hack" — silent fallbacks turn config typos into deployments that look like they're working but emit ephemeral tokens that break across restarts. The shape that landed:

- `jwt.signing_alg=RS256` requires either `jwt.private_key_path` (production path) or `jwt.ephemeral_signing_key: true` (explicit opt-in for tests).
- Neither set → fail loudly with a clear error: "set jwt.private_key_path or jwt.ephemeral_signing_key=true".

**How to apply:**
- Look for places where I'm about to add a "default to convenient behavior" branch. Reframe as "default to error; require explicit opt-in for the convenience."
- The opt-in flag name should make intent obvious: `ephemeral_signing_key`, `dev_auto_generate`, `test_only_*`. Avoid bare booleans like `auto: true`.
- Production deployments should never silently get the test-friendly behavior. Misconfiguration in prod must be a loud failure, not a working-but-broken state.
- This is part of the broader "reference deployment, not POC" framing in #194 — the reference server (`cmd/oneauth-server`) should fail loudly, not paper over gaps.

**Why this is a memory and not just a code review note:** the temptation to add silent-fallback "convenience" defaults recurs every time a new config knob lands. Codifying the pattern means the next config addition starts from explicit-opt-in instead of defaulting to convenience-fallback and getting pushback after the fact.
