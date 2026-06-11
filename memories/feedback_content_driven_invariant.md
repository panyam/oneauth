---
name: feedback_content_driven_invariant
description: When widening a predicate, prefer content-driven (inspect bytes/header) over identifier-driven (algorithm/type string) when the identifier can lie. Pair with a safe-from-collision marker that distinguishes the new shape from anything previously stored.
metadata:
  type: feedback
---

PR 291 (#248) widened `EncryptedKeyStorage`'s encryption predicate from "is HMAC algorithm" to "is HMAC OR PEM header type contains PRIVATE." The original gate (algorithm field on `KeyRecord`) would have missed private keys persisted under non-JWT algorithm strings like `ssh-ed25519`. The widened gate inspects the actual key bytes — a `pem.Decode` whose header type contains "PRIVATE" — because that's the artifact actually being persisted, not the metadata label.

The non-obvious half is the *read* path. The write side picks ciphertext-vs-plaintext from input shape. The read side has to distinguish "still plaintext PEM" (public key, legacy migration) from "encrypted bytes that decrypt to a PEM" without re-running the encrypt decision. The solution: AES-GCM's random-nonce prefix means ciphertext can **never** start with `-----BEGIN`. So `bytes.HasPrefix(stored, []byte("-----BEGIN"))` is a safe-from-collision marker for "this is a plaintext PEM." No false positives possible from our own encrypt() output.

**Why:** A predicate widening that misses cases silently is worse than the original narrow predicate — silent data leaks (plaintext private keys) instead of a fail-loud rejection. Content-driven inspection with a collision-proof marker is the pattern that scales as new consumer types appear.

**How to apply:**
- When a gate currently checks a label/type/enum field, ask whether a future caller could legitimately use a *different* label for the same underlying shape. If yes, switch to content inspection.
- When you need to distinguish "stored shape A" from "stored shape B" on read, find a marker that can never appear in shape B (random-prefix output, magic byte, PEM header, etc.). Document the impossibility argument inline — that's the load-bearing security claim.
- The argument has to actually hold. "AES-GCM nonce is random" isn't enough; you need "AES-GCM output bytes 0-11 are uniform random," and `-----BEGIN` is 10 specific ASCII bytes (1 / 2^80 collision probability). Spell it out in the doc comment so future refactors don't break the invariant.

Related: [[feedback_god_interface]] (decompose by concern — the encrypt decision is now content-typed, not algorithm-typed), [[feedback_explicit_opt_in_for_dev_hacks]] (this is the opposite — content-driven keeps the safe default automatic without caller opt-in).
