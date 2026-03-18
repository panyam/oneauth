---
name: Avoid god interfaces — decompose by concern
description: When proposing interfaces with multiple concerns (storage + lookup + encryption + rotation), decompose into focused interfaces early. The user caught this pattern during the kid/KeyStore work.
type: feedback
---

Don't embed rotation/encryption/kid-lookup state into the same interface as basic key CRUD. When a decorator (like EncryptedKeyStore) has to forward every method manually, that's a smell — the interface is too wide.

**Why:** During the kid-in-JWTs work (#25), the original plan embedded `PreviousKey`, `PreviousKid`, `PreviousExpiresAt` directly in the key entry and added `RotatableKeyStore` (a fat interface). The user pushed back: "our KeyStore is becoming a god interface and each change is hitting every implementation." Three workarounds piled up in one PR before we refactored.

**How to apply:** When proposing a new capability on an existing interface, check: (1) does every backend need to implement this? (2) does the decorator need another forwarding method? If yes to either, it's probably a separate concern. Use a `KeyRecord` struct pattern — return all fields in one call so adding fields doesn't change the interface. Separate read (`KeyLookup`) from write (`KeyStorage`) so read-only consumers (JWKSKeyStore, middleware) don't carry write baggage.
