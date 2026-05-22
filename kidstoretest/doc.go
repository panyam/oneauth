// Package kidstoretest provides a shared, test-only contract suite that every
// KidStorage backend (in-memory KidStore, FS, GORM, GAE) runs against its own
// factory, mirroring keystoretest.
//
// <!-- design:start -->
// This package owns the KidStorage contract: a single, test-only suite that
// every backend (in-memory KidStore, FS, GORM, GAE) runs against its own
// factory, mirroring keystoretest. It defines no production code — only the
// behavioral guarantees each KidStorage must satisfy. A backend supplies a
// Factory and calls RunAll, which executes every contract test as a named
// subtest, keeping all implementations in lock-step.
//
// # ENTITIES
//
// Factory — function alias producing a fresh keys.KidStorage per test, so one
// suite can drive every backend without knowing the backend.
//
// RunAll — entry point running the complete contract as named subtests against
// a factory; one call per backend.
//
// TestAddAndGetByKid — asserts Add then GetKeyByKid round-trips key bytes,
// algorithm, clientID, and kid.
//
// TestGetByUnknownKid — asserts an unknown kid returns keys.ErrKidNotFound.
//
// TestGetKeyByClientIDAlwaysNotFound — asserts GetKey by clientID always
// returns keys.ErrKeyNotFound, since a kid-indexed store has no clientID index.
//
// TestOverwriteSameKid — asserts re-Adding the same kid replaces key,
// algorithm, and clientID (Add is upsert-by-kid).
//
// TestRemoveIdempotent — asserts Remove of an absent kid is nil and Remove of a
// present kid clears it; Remove is intentionally idempotent, unlike
// KeyStorage.DeleteKey.
//
// TestExpiredKidNotReturned — asserts a past-expiry kid returns
// keys.ErrKidNotFound, so reads filter expired entries even before any sweep.
//
// TestZeroExpiryNeverExpires — asserts a zero time.Time expiry means the kid is
// always retrievable (zero is the no-expiry sentinel).
//
// TestCleanExpired — asserts CleanExpired sweeps only expired kids and
// physically frees the slot for re-Add, confirming the backing row/file is
// removed and not merely hidden.
//
// TestAsymmetricKeyRoundTrip — asserts an RSA public-key PEM stored under a
// computed kid round-trips with RS256, proving PEM bytes are preserved verbatim.
//
// TestPersistence — asserts the store reads back what it wrote within one
// instance; trivial for in-memory but exercises the real storage layer for
// FS/GORM/GAE. Cross-restart proof lives in backend-specific tests.
// <!-- design:end -->
package kidstoretest
