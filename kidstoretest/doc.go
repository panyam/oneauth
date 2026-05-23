// Package kidstoretest provides a shared, test-only contract suite that
// every keys.KidStorage backend runs against its own factory.
//
// This package owns the KidStorage contract: a single suite that each
// backend — the in-memory KidStore, the filesystem store, the GORM
// store, and the GAE store — drives through a per-test Factory,
// mirroring keystoretest. It defines no production code, only the
// behavioral guarantees every KidStorage must satisfy. A backend
// supplies a Factory and calls RunAll, which executes the full contract
// as named subtests so every implementation stays in lock-step.
//
// ENTITIES
//
// Factory — function alias producing a fresh keys.KidStorage per test
// invocation. Lets one suite drive every backend without knowing how
// the backend is constructed.
//
// RunAll — entry point running the complete KidStorage contract as
// named subtests against a factory. One call per backend keeps coverage
// in lock-step across all implementations.
//
// TestAddAndGetByKid — asserts Add then GetKeyByKid round-trips key
// bytes, algorithm, clientID, and kid. Establishes the baseline
// write-read contract every backend must honor.
//
// TestGetByUnknownKid — asserts an unknown kid returns
// keys.ErrKidNotFound. Pins the sentinel error so callers can branch on
// miss versus failure portably.
//
// TestGetKeyByClientIDAlwaysNotFound — asserts GetKey by clientID
// always returns keys.ErrKeyNotFound on a kid-indexed store. A kid
// store has no clientID index; lookup-by-client is meaningless and must
// fail uniformly.
//
// TestOverwriteSameKid — asserts re-Adding the same kid replaces key,
// algorithm, and clientID. Add is upsert-by-kid; backends must not
// silently keep stale rows.
//
// TestRemoveIdempotent — asserts Remove of an absent kid is nil and
// Remove of a present kid clears it. KidStorage.Remove is intentionally
// idempotent, unlike KeyStorage.DeleteKey which errors on miss.
//
// TestExpiredKidNotReturned — asserts a kid with a past expiry returns
// keys.ErrKidNotFound on read. Reads must filter expired entries even
// before any sweep runs.
//
// TestZeroExpiryNeverExpires — asserts a zero time.Time expiry keeps
// the kid always retrievable. Zero is the no-expiry sentinel and must
// not be treated as expired-at-epoch.
//
// TestCleanExpired — asserts CleanExpired sweeps only expired kids and
// physically frees the slot for re-Add. Confirms the sweep removes the
// backing row or file, not just hides it from reads.
//
// TestAsymmetricKeyRoundTrip — asserts an RSA public-key PEM stored
// under a computed kid round-trips with RS256. Backends must preserve
// PEM bytes verbatim, not just symmetric secrets.
//
// TestPersistence — asserts the store reads back what it wrote within
// one instance. Trivial for in-memory but exercises the real storage
// layer for FS, GORM, and GAE; cross-restart proof lives in
// backend-specific tests.
package kidstoretest
