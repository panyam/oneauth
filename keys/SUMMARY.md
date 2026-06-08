# keys/ — Key Storage, KID Tracking, JWKS

JWT signing key management: storage interfaces, in-memory and encrypted backends, key-ID tracking for rotation, and JWKS endpoint serving/fetching.

## Contents
- **keystore.go** — `KeyRecord`, `KeyLookup`, `KeyStorage` interfaces, `InMemoryKeyStore`, error vars
- **encrypted.go** — `EncryptedKeyStorage` decorator (AES-256-GCM at rest for HMAC secrets)
- **kid.go** — `KidStorage` interface, `KidStore` (in-memory grace-period key retention), `CompositeKeyLookup`. Persistent `KidStorage` backends live in `stores/{fs,gorm,gae}`.
- **jwks_handler.go** — `JWKSHandler` (serves `/.well-known/jwks.json`)
- **jwks_keystore.go** — `JWKSKeyStore` (fetches remote JWKS), option functions

## Tracing (SEP-414 / #254)

Both `JWKSHandler` and `JWKSKeyStore` accept an optional `*trace.TracerProvider`. When set:

- `JWKSHandler.ServeHTTP` extracts the inbound W3C `traceparent` and emits a `oneauth.jwks.serve` span (attr `jwks.keys_returned`, `http.response.status_code`).
- `JWKSKeyStore.GetKeyByKid` emits `oneauth.jwks.key_lookup` (attrs `jwks.kid`, `jwks.cache_hit`).
- `JWKSKeyStore.refresh` (on cache-miss or ticker) emits `oneauth.jwks.refresh` and injects a `traceparent` on the outbound HTTP fetch so OTel-aware JWKS endpoints stitch in.

`nil` keeps every path on a no-op tracer with zero allocation cost. Configure via `WithTracerProvider(tp)` on `JWKSKeyStore`; set the `TracerProvider` field directly on `JWKSHandler`.

## Dependencies
`utils/` for crypto helpers, `tracing/` for SEP-414 propagation. No dependency on `core/`.
