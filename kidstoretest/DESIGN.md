# kidstoretest

Shared conformance test suite that every `keys.KidStorage` backend (in-memory KidStore, FS, GORM, GAE) drives via its own `Factory`. One call to `RunAll` exercises the full contract — add/get, miss semantics, upsert-by-kid, idempotent remove, expiry filtering, sweep, asymmetric PEM round-trip, and persistence — so each backend stays in lock-step without duplicating assertions.

## Contents

- [Entities](#entities)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `Factory` | type | Function alias producing a fresh `keys.KidStorage` for each test invocation. | Lets one suite drive every backend; each impl supplies its own constructor without the suite knowing the backend. |
| `RunAll` | func | Entry point running the complete KidStorage contract as named subtests against a factory. | Single call per backend keeps coverage in lock-step across all implementations. |
| `TestAddAndGetByKid` | func | Asserts `Add` then `GetKeyByKid` round-trips key bytes, algorithm, clientID, and kid. | Establishes the baseline write-read contract every backend must honor. |
| `TestGetByUnknownKid` | func | Asserts an unknown kid returns `keys.ErrKidNotFound`. | Pins the sentinel error so callers can branch on miss vs failure. |
| `TestGetKeyByClientIDAlwaysNotFound` | func | Asserts `GetKey` by clientID always returns `keys.ErrKeyNotFound` on a kid-indexed store. | A kid store is not clientID-indexed; lookup-by-client is meaningless and must fail uniformly. |
| `TestOverwriteSameKid` | func | Asserts re-`Add`ing the same kid replaces key, algorithm, and clientID. | `Add` is upsert-by-kid; backends must not silently keep stale rows. |
| `TestRemoveIdempotent` | func | Asserts `Remove` of an absent kid is nil and `Remove` of a present kid clears it. | `KidStorage.Remove` is intentionally idempotent, unlike `KeyStorage.DeleteKey` which errors on miss. |
| `TestExpiredKidNotReturned` | func | Asserts a kid with a past expiry returns `keys.ErrKidNotFound` on read. | Reads must filter expired entries even before any sweep runs. |
| `TestZeroExpiryNeverExpires` | func | Asserts a zero `time.Time` expiry means the kid is always retrievable. | Zero value is the no-expiry sentinel and must not be treated as expired-at-epoch. |
| `TestCleanExpired` | func | Asserts `CleanExpired` sweeps only expired kids and physically frees the slot for re-`Add`. | Confirms the sweep removes the backing row/file, not just hides it from reads. |
| `TestAsymmetricKeyRoundTrip` | func | Asserts an RSA public-key PEM stored under a computed kid round-trips with `RS256`. | Backends must preserve PEM bytes verbatim, not just symmetric secrets. |
| `TestPersistence` | func | Asserts the store reads back what it wrote within one instance. | Trivial for in-memory but exercises the real storage layer for FS/GORM/GAE; cross-restart proof lives in backend-specific tests. |

## Gotchas

- **`Add` is upsert by kid.** A second `Add` on the same kid replaces every field — key bytes, algorithm, *and* clientID — not just the value. Backends that treat `Add` as insert-only will fail `TestOverwriteSameKid`.
- **`Remove` is idempotent, `KeyStorage.DeleteKey` is not.** `KidStorage.Remove` on a missing kid must return `nil`; the sibling `KeyStorage` contract returns `ErrKeyNotFound` on the same shape. Don't unify these.
- **`GetKey(clientID)` must always return `ErrKeyNotFound`.** A `KidStorage` is indexed by kid, not by client — even when a kid for that client exists, `GetKey` must fail. This is the documented split between the two storage roles.
- **Zero `time.Time` is "never expires", not "expired at epoch".** Reads and `CleanExpired` must special-case the zero value; treating it as a past timestamp will sweep keys that were meant to live forever.
- **Reads filter expired entries even without a sweep.** `GetKeyByKid` on a past-expiry kid must return `ErrKidNotFound` before `CleanExpired` ever runs, so callers never see stale material.
- **`CleanExpired` must physically remove the row/file.** The re-`Add` step in `TestCleanExpired` would collide with stale state if the sweep only soft-hid the entry.

## Depends on

- [`keys/`](../keys/DESIGN.md) — `KidStorage`, `ErrKidNotFound`, `ErrKeyNotFound`
- [`utils/`](../utils/DESIGN.md) — `GenerateRSAKeyPair`, `ComputeKid`
