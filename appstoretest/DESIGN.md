# appstoretest

A backend-agnostic contract test suite for `admin.AppRegistrationStore`. Each storage backend (inmem, fs, gorm) supplies a `Factory` that returns a fresh store, then calls `RunAll` to execute every test under a named subtest. New contract guarantees are added once here and immediately apply to every backend, keeping the three implementations behaviorally interchangeable for DCR and admin flows.

## Contents

- [Entities](#entities)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `Factory` | type | `func(t *testing.T) admin.AppRegistrationStore` returning a fresh store per test. | Inverts construction so the suite stays backend-agnostic; backends own temp dirs, DB handles, and cleanup via `t.Cleanup`. |
| `RunAll` | func | Single entry point that registers every `Test*` as a named subtest. | Backends call it once; adding a new contract test here applies to every backend without editing call sites. |
| `TestSaveAndGet` | func | Round-trips a registration through `SaveApp` then `GetApp`. | Smoke test that read and write resolve to the same logical key. |
| `TestNotFound` | func | `GetApp` on a missing `client_id` must return `admin.ErrAppNotFound`. | Pins the sentinel-error contract callers rely on for branching. |
| `TestDeleteApp` | func | Save, delete, then read returns `ErrAppNotFound`. | Confirms deletes are observable, not merely flagged. |
| `TestDeleteNonexistent` | func | Deleting an unknown `client_id` returns `ErrAppNotFound`. | Matches `KeyStorage.DeleteKey` semantics so callers don't special-case backends. |
| `TestOverwriteApp` | func | Second `SaveApp` on the same `client_id` replaces (not merges) the prior record. | Locks in upsert semantics so DCR re-registration is deterministic. |
| `TestListApps` | func | After saving N apps, `ListApps` returns all N. | Forces enumeration completeness without relying on insertion order. |
| `TestListAppsEmpty` | func | `ListApps` on a fresh store returns an empty slice and nil error. | Forbids backends from conflating "no apps" with a failure. |
| `TestPersistence` | func | Read-after-write on the same handle must see the write. | Catches buffered-write or uncommitted-transaction bugs in FS/GORM. |
| `TestAllFieldsRoundTrip` | func | Populates every `AppRegistration` field and verifies each on read-back. | Catches serialization gaps (e.g., GORM forgetting to JSON-encode `RedirectURIs`, `GrantTypes`, `AuthorizationDetailsTypes`). |

## Gotchas

- **Each test gets a fresh store.** Every `Test*` function calls `factory(t)` at the top, so no state leaks between subtests. Backends must build that isolation into the factory (temp dirs, fresh DB schemas).
- **Sentinel-error identity, not just type.** Tests use `err != admin.ErrAppNotFound` (exact comparison), so backends must return the canonical sentinel — wrapping with `fmt.Errorf("%w", ErrAppNotFound)` will fail the suite.
- **Delete-of-missing returns `ErrAppNotFound`, not nil.** Counterintuitive but deliberate — matches the `KeyStorage.DeleteKey` contract and lets callers detect already-deleted state.
- **`TestListApps` sorts results before comparing.** Backends are free to return in any order; the suite normalizes. Don't add tests that depend on a specific order.
- **`TestAllFieldsRoundTrip` is the canary for new `AppRegistration` fields.** When a new field is added upstream, this test must be extended or backend serialization gaps (especially in GORM, where slice fields need explicit JSON columns) will silently ship.

## Depends on

- [`admin/`](../admin/DESIGN.md) — `AppRegistrationStore`, `AppRegistration`, `ErrAppNotFound`
