// Package keystoretest is the shared contract test suite that every KeyStore
// backend (inmem, gorm, fs, gae) runs against its own factory.
//
// <!-- design:start -->
// This package owns the behavioral contract for keys.KeyStorage. It is
// test-only: backends import it from their *_test.go files, pass a Factory
// that mints a fresh store, and call RunAll to execute every contract case as
// a named subtest. Centralizing the suite here means a new invariant is
// written once and instantly enforced across all backends, and the canonical
// error sentinels (keys.ErrKeyNotFound, keys.ErrKidNotFound) and kid
// computation (utils.ComputeKid) are exercised uniformly so JWKS and verify
// paths agree no matter which store is plugged in.
//
// # ENTITIES
//
// Factory — function type each backend supplies to mint a fresh
// keys.KeyStorage per test; the indirection lets one suite drive every backend
// without importing any concrete store.
//
// RunAll — single entry point that runs the full suite as named subtests
// against a factory, so adding a case extends every backend's coverage at once.
//
// TestRegisterAndGet — asserts PutKey then GetKey round-trips key bytes and
// algorithm for HS256, pinning the basic store/retrieve invariant.
//
// TestNotFound — asserts GetKey on an unknown client returns
// keys.ErrKeyNotFound, forcing the same sentinel everywhere.
//
// TestMultipleHosts — asserts distinct clients keep isolated key material,
// guarding against cross-tenant aliasing.
//
// TestDeleteKey — asserts DeleteKey removes a key so subsequent GetKey returns
// ErrKeyNotFound, confirming deletion is observable.
//
// TestDeleteNonexistent — asserts deleting an absent key returns
// keys.ErrKeyNotFound, locking idempotent-delete semantics to the sentinel.
//
// TestOverwriteKey — asserts a second PutKey on the same client replaces both
// key bytes and algorithm, pinning upsert semantics.
//
// TestListKeys — asserts ListKeyIDs returns exactly the registered client IDs,
// guaranteeing enumeration completeness.
//
// TestListKeysEmpty — asserts ListKeyIDs on an empty store returns an empty
// slice without error.
//
// TestPersistence — asserts a key written via the factory store is readable
// back, codifying that factory-returned stores share their backing storage.
//
// TestKidResolverBasic — asserts GetKeyByKid resolves an HS256 key by its
// computed kid and rejects unknown kids with ErrKidNotFound.
//
// TestKidResolverAsymmetric — asserts ComputeKid on stored RSA PEM bytes equals
// ComputeKid on the parsed key, and GetKeyByKid resolves it.
//
// TestGetCurrentKid — asserts GetKey populates KeyRecord.Kid matching the
// computed kid, so callers never recompute it inconsistently.
//
// TestRegisterAndGetAsymmetricKey — asserts an RS256 public-key PEM round-trips
// and DecodeVerifyKey parses it into *rsa.PublicKey.
// <!-- design:end -->
package keystoretest
