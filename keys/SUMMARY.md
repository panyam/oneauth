# keys/ — Key Storage, KID Tracking, JWKS

JWT signing key management: storage interfaces, in-memory and encrypted backends, key-ID tracking for rotation, and JWKS endpoint serving/fetching.

## Contents
- **keystore.go** — `KeyRecord`, `KeyLookup`, `KeyStorage` interfaces, `InMemoryKeyStore`, error vars
- **encrypted.go** — `EncryptedKeyStorage` decorator (AES-256-GCM at rest for HMAC secrets)
- **kid.go** — `KidStore` (grace-period key retention), `CompositeKeyLookup`
- **jwks_handler.go** — `JWKSHandler` (serves `/.well-known/jwks.json`)
- **jwks_keystore.go** — `JWKSKeyStore` (fetches remote JWKS), option functions

## Dependencies
`utils/` for crypto helpers. No dependency on `core/`.
