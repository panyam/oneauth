// Package keystoretest is the shared contract test suite that every
// keys.KeyStorage backend runs against its own factory.
//
// Backends (inmem, gorm, fs, gae) import this package from their *_test.go
// files, supply a Factory that mints a fresh store, and call RunAll to
// execute every contract case as a named subtest. Centralizing the suite
// here means a new invariant is written once and instantly enforced across
// all backends, and the canonical error sentinels (keys.ErrKeyNotFound,
// keys.ErrKidNotFound) and kid computation (utils.ComputeKid) are exercised
// uniformly so JWKS and verify paths agree no matter which store is
// plugged in.
//
// ENTITIES
//
// Factory — function type each backend supplies to mint a fresh
// keys.KeyStorage per test. Indirection lets one suite drive every backend
// without importing any concrete store.
//
// RunAll — single entry point that runs the full suite as named subtests
// against a factory. Adding a case here extends every backend's coverage
// at once.
//
// TestRegisterAndGet — asserts PutKey then GetKey round-trips key bytes
// and algorithm for HS256. Pins the basic store/retrieve invariant for
// symmetric keys.
//
// TestNotFound — asserts GetKey on an unknown client returns
// keys.ErrKeyNotFound. Forces the same sentinel error everywhere instead
// of a generic miss.
//
// TestMultipleHosts — asserts distinct clients keep isolated key material.
// Guards against cross-tenant aliasing.
//
// TestDeleteKey — asserts DeleteKey removes a key so subsequent GetKey
// returns ErrKeyNotFound. Confirms deletion is observable to readers.
//
// TestDeleteNonexistent — asserts deleting an absent key returns
// keys.ErrKeyNotFound. Locks idempotent-delete semantics to the sentinel.
//
// TestOverwriteKey — asserts a second PutKey on the same client replaces
// both key bytes and algorithm. Pins upsert semantics so rotations are
// honored.
//
// TestListKeys — asserts ListKeyIDs returns exactly the registered client
// IDs. Guarantees enumeration completeness for JWKS publication.
//
// TestListKeysEmpty — asserts ListKeyIDs on an empty store returns an
// empty slice without error. Empty enumeration must not error or return
// nil-vs-empty oddities.
//
// TestPersistence — asserts a key written via the factory store is
// readable back. Codifies that factory-returned stores share their
// backing storage.
//
// TestKidResolverBasic — asserts GetKeyByKid resolves an HS256 key by
// computed kid and rejects unknown kids with ErrKidNotFound. Verify paths
// look up by kid, so the resolution contract must hold.
//
// TestKidResolverAsymmetric — asserts ComputeKid on stored RSA PEM equals
// ComputeKid on the parsed key, and GetKeyByKid resolves it. JWKS and
// verify must agree on the same thumbprint for asymmetric keys.
//
// TestGetCurrentKid — asserts GetKey populates KeyRecord.Kid matching the
// computed kid. Callers never recompute kid inconsistently across
// backends.
//
// TestRegisterAndGetAsymmetricKey — asserts an RS256 public-key PEM
// round-trips and DecodeVerifyKey parses it into *rsa.PublicKey. Pins the
// PEM-in / parsed-key-out invariant for asymmetric verify.
package keystoretest
