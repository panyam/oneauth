# keystoretest

A single-file conformance suite that every `keys.KeyStorage` backend in the repo (inmem, gorm, fs, gae) drives against its own constructor. A backend's `_test.go` builds a `Factory` closure that mints a fresh store per subtest, then calls `RunAll`; the suite exercises Put/Get/Delete/List, the `ErrKeyNotFound` and `ErrKidNotFound` sentinels, upsert-on-Put, kid resolution for both symmetric and RSA keys, that `KeyRecord.Kid` is populated on read, and that PEM bytes round-trip unmangled. The intent is that any new backend gets the entire matrix for free, and that any breakage of the cross-backend contract surfaces as a failed subtest with a stable name.

## Contents

- [Entities](#entities)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `Factory` | type | Function signature backends provide so each subtest gets a fresh `KeyStorage` instance. | Per-test isolation without coupling the suite to any backend's constructor or cleanup. |
| `RunAll` | func | Registers every `Test*` helper as a `t.Run` subtest against the given `Factory`. | Single entry point so a backend's `_test.go` opts into the full conformance matrix with one line. |
| `TestRegisterAndGet` | func | Puts an HS256 secret, reads it back, asserts byte equality and algorithm. | Smoke test for the most basic Put/Get round-trip every backend must satisfy. |
| `TestNotFound` | func | `GetKey` on an unknown client must return `keys.ErrKeyNotFound` (not a wrapped error). | Pins the sentinel error contract callers rely on for branchless miss-handling. |
| `TestMultipleHosts` | func | Verifies two distinct `ClientID`s hold distinct key material with no cross-talk. | Catches backends that accidentally namespace-collapse or share a single bucket. |
| `TestDeleteKey` | func | Put, delete, then assert subsequent `GetKey` returns `ErrKeyNotFound`. | Ensures delete is observable to readers, not just locally cached. |
| `TestDeleteNonexistent` | func | Deleting an unknown `ClientID` must return `ErrKeyNotFound`, not nil. | Forces backends to distinguish "no-op delete" from "successful delete" loudly. |
| `TestOverwriteKey` | func | Re-Putting the same `ClientID` swaps both key material and algorithm in place. | Confirms upsert semantics so rotations (HS256 to HS512, key change) are honoured. |
| `TestListKeys` | func | After three Puts, `ListKeyIDs` returns exactly those three `ClientID`s. | Validates the admin/iteration surface every JWKS-like consumer depends on. |
| `TestListKeysEmpty` | func | `ListKeyIDs` on a fresh store returns an empty slice, not nil-panic or error. | Edge case where many backends would otherwise leak an "empty bucket" sentinel. |
| `TestPersistence` | func | Writes then re-reads through the factory-provided handle to prove data survives. | Single-process persistence floor; persistent backends are expected to satisfy it via shared storage. |
| `TestKidResolverBasic` | func | Stores an HS256 secret then resolves it via `GetKeyByKid` using `utils.ComputeKid` as oracle. | Asserts the kid-index path matches the `ClientID` path for symmetric keys. |
| `TestKidResolverAsymmetric` | func | Stores an RSA public key PEM then resolves by kid computed off both PEM bytes and parsed `*rsa.PublicKey`. | Pins the invariant that `ComputeKid(PEM) == ComputeKid(parsedKey)` so backends can index either way. |
| `TestGetCurrentKid` | func | `GetKey` must populate `KeyRecord.Kid` with the canonical thumbprint, and miss must return `ErrKeyNotFound`. | Callers read `rec.Kid` to stamp JWT headers; backends that forget to fill it would break signing silently. |
| `TestRegisterAndGetAsymmetricKey` | func | Round-trips an RSA public key PEM through `PutKey`/`GetKey` and decodes it back via `utils.DecodeVerifyKey`. | Guards the PEM-as-bytes contract so storage layers don't mangle or re-encode key material. |

## Gotchas

- **`Factory` is called once per subtest, not once per suite.** `RunAll` invokes `factory(t)` inside each `t.Run`, so a backend that returns the same handle every call gets shared state across subtests; a backend that returns a fresh handle gets isolation. `TestPersistence` only works because the factory returns a handle whose underlying storage outlives the call — file/DB/GAE backends must point all returned handles at the same path/connection, while inmem backends trivially satisfy this with the same map.
- **`ErrKeyNotFound` vs `ErrKidNotFound` are distinct sentinels.** `GetKey` misses must surface `keys.ErrKeyNotFound`, `GetKeyByKid` misses must surface `keys.ErrKidNotFound`. `==` comparison is used (not `errors.Is`), so backends that wrap the error will fail these tests by design.
- **`DeleteKey` on an absent ClientID is *not* a no-op.** It must return `ErrKeyNotFound`. Backends modelled on `map[string]X` with a plain `delete()` will accidentally pass with a nil return and fail `TestDeleteNonexistent`.
- **`PutKey` is upsert.** `TestOverwriteKey` requires that re-putting the same `ClientID` replaces both `Key` and `Algorithm`. Append-only or first-write-wins storage is not a valid backend.
- **`KeyRecord.Key` is `any`, but every backend in scope stores it as `[]byte`.** Every subtest does `rec.Key.([]byte)` unchecked-ish; a backend that round-trips the value as anything else (e.g. already-parsed `*rsa.PublicKey`) will panic the assertion. For RS256 the bytes are expected to be the PEM as originally written, not a re-encoded canonical form.
- **`KeyRecord.Kid` is computed by the backend on write, surfaced on read.** `TestGetCurrentKid` asserts `rec.Kid == utils.ComputeKid(secret, alg)`. Backends must either persist the kid alongside the record or recompute it on `GetKey` using the same `utils.ComputeKid` algorithm — otherwise JWT headers stamped from `rec.Kid` won't match what the JWKS endpoint advertises.
- **No encryption-at-rest assertions live here.** This suite covers the plain `keys.KeyStorage` contract; the `EncryptedKeyStorage` wrapper has its own coverage elsewhere. A backend can pass this suite while still leaking secrets at rest.
- **The suite imports `keys` and `utils` directly**, which is the intended cross-package boundary — `depends_on` is left empty in the sidecar because the test package has no runtime consumers and isn't a participant in the doc-drift graph.

## Depends on

- [`keys/`](../keys/DESIGN.md) — `KeyStorage`, `KeyRecord`, `ErrKeyNotFound`, `ErrKidNotFound`
- [`utils/`](../utils/DESIGN.md) — `ComputeKid`, `GenerateRSAKeyPair`, `DecodeVerifyKey`
