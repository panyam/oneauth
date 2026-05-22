// Package appstoretest provides a shared contract test suite that every
// AppRegistrationStore backend (inmem, fs, gorm) runs against its own factory
// to prove uniform behavior.
//
// <!-- design:start -->
// This package is test-only. It owns the behavioral contract for
// admin.AppRegistrationStore: rather than each backend re-deriving its own
// tests, every implementation hands a Factory to RunAll and inherits the same
// suite. Centralizing the contract here means a new invariant added once is
// enforced across inmem, fs, and gorm simultaneously, and divergent backend
// behavior surfaces as a failing shared test instead of an undocumented gap.
// It deliberately does not construct stores itself — backends inject creation
// via Factory so the suite stays storage-agnostic.
//
// # ENTITIES
//
// Factory — function type a backend supplies that returns a fresh
// AppRegistrationStore per test, inverting construction so the suite never
// depends on a concrete backend.
//
// RunAll — entry point running the full suite of contract subtests against one
// factory; the single call site keeps every backend's coverage in lock-step.
//
// TestSaveAndGet — asserts SaveApp then GetApp returns the saved registration,
// the baseline read-after-write contract.
//
// TestNotFound — asserts GetApp on a missing client_id returns
// admin.ErrAppNotFound, pinning the sentinel-error contract for misses.
//
// TestDeleteApp — asserts DeleteApp removes a registration and a later GetApp
// returns ErrAppNotFound, confirming deletion is observable.
//
// TestDeleteNonexistent — asserts deleting a missing client_id returns
// ErrAppNotFound, aligning delete-miss semantics with KeyStorage.DeleteKey.
//
// TestOverwriteApp — asserts re-saving an existing client_id replaces stored
// metadata, locking down upsert semantics for SaveApp.
//
// TestListApps — asserts ListApps returns every saved registration, verifying
// enumeration completeness independent of insertion order.
//
// TestListAppsEmpty — asserts ListApps on a fresh store returns an empty slice
// rather than an error, so callers need not special-case empty.
//
// TestPersistence — asserts a saved registration is visible to a subsequent
// read on the same handle, catching write-buffering bugs in persistent
// backends (FS, GORM); trivially true for InMem.
//
// TestAllFieldsRoundTrip — asserts every AppRegistration field survives a
// SaveApp/GetApp round-trip, catching backend serialization gaps such as GORM
// failing to JSON-encode slice fields.
// <!-- design:end -->
package appstoretest
