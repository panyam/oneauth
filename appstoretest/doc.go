// Package appstoretest shared contract test suite that every
// AppRegistrationStore backend runs against its own factory to prove
// uniform behavior.
//
// This package is test-only. It owns the behavioral contract for
// admin.AppRegistrationStore: rather than each backend (inmem, fs, gorm)
// re-deriving its own tests, every implementation hands a Factory to
// RunAll and inherits the same suite. Centralizing the contract here
// means a new invariant added once is enforced across all backends, and
// divergent behavior surfaces as a failing shared test instead of an
// undocumented gap. The suite deliberately does not construct stores
// itself — backends inject creation via Factory so the suite stays
// storage-agnostic.
//
// ENTITIES
//
// Factory — function type a backend supplies that returns a fresh
// AppRegistrationStore per test. Inverts construction so the suite stays
// storage-agnostic and each backend controls setup/teardown.
//
// RunAll — entry point that runs the complete suite of contract subtests
// against one factory. Single call site keeps every backend's coverage
// in lock-step.
//
// TestSaveAndGet — asserts SaveApp then GetApp returns the saved
// registration. Baseline read-after-write contract every backend must
// honor.
//
// TestNotFound — asserts GetApp on a missing client_id returns
// admin.ErrAppNotFound. Pins the sentinel-error contract so callers can
// branch on a typed miss.
//
// TestDeleteApp — asserts DeleteApp removes a registration and a later
// GetApp returns ErrAppNotFound. Confirms deletion is observable, not
// just a no-op flag.
//
// TestDeleteNonexistent — asserts deleting a missing client_id returns
// ErrAppNotFound. Aligns delete-miss semantics with KeyStorage.DeleteKey
// so backends agree on the error.
//
// TestOverwriteApp — asserts re-saving an existing client_id replaces
// stored metadata. Locks down upsert (not append/conflict) semantics for
// SaveApp.
//
// TestListApps — asserts ListApps returns every saved registration.
// Verifies enumeration completeness independent of insertion order.
//
// TestListAppsEmpty — asserts ListApps on a fresh store returns an empty
// slice, not an error. Distinguishes "no apps" from a failure so callers
// need not special-case empty.
//
// TestPersistence — asserts a saved registration is visible to a
// subsequent read on the same handle. Catches write-buffering bugs in
// persistent backends (FS, GORM); trivially true for InMem.
//
// TestAllFieldsRoundTrip — asserts every AppRegistration field survives
// a SaveApp/GetApp round-trip. Catches backend serialization gaps such
// as GORM failing to JSON-encode slice fields.
package appstoretest
