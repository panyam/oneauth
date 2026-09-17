---
name: encoding-layer-normalization-defeats-text-tampering
description: "Tamper with decoded bytes, not with encoded text — Go's base64 decoder ignores trailing bits, so flipping the last character of a signature often decodes identically. Lesson from the DPoP proof tests (#336, PR 370)."
metadata:
  node_type: memory
  type: feedback
---

A negative test that corrupts a credential must corrupt it **after decoding**. Editing the encoded text can be a no-op, because the decoder normalizes away the part you changed.

**Why:** Concrete case: `TestDPoPProof_RejectsTamperedSignature` flipped the last character of a JWT's base64url signature segment. An ES256 signature is 64 bytes, which base64url encodes in 86 characters carrying 516 bits — 4 more than the signature has. Go's `base64.RawURLEncoding` does not reject non-zero trailing bits, so flipping that final character frequently decodes to the identical 64 bytes and the signature still verifies. The test passed roughly 9 runs in 10 and failed the rest. It was caught by the red-check: disabling an unrelated production check made it fail, which is not something a correct test does. Fix was to decode the segment, flip a bit in byte 0, and re-encode.

**How to apply:**
- Mutate the **decoded** value (`base64.RawURLEncoding.DecodeString` → flip a byte → re-encode) whenever a test needs an invalid signature, hash, or key.
- Run new negative tests with `-count=20` before trusting them. A test that fails intermittently is usually asserting something weaker than it looks.
- Read a red-check failure in an *unrelated* test as a signal about the test, not noise. That is how this one surfaced.
- The general shape: the encoding layer is more permissive than the spec, so a check that operates on the encoded form is checking something the system does not care about. See [[feedback_capture_the_artifact]] for the serialization variant of the same trap.
