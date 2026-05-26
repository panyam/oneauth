# keystoretest

A single-file conformance suite that every `keys.KeyStorage` backend in the repo (inmem, fs, gorm, gae) drives against its own constructor. A backend's `_test.go` builds a `Factory` closure that mints a fresh store per subtest, then calls `RunAll`; the suite exercises Put/Get/Delete/List, the `ErrKeyNotFound` and `ErrKidNotFound` sentinels, upsert-on-Put, kid resolution for both symmetric and RSA keys, that `KeyRecord.Kid` is populated on read, and that PEM bytes round-trip unmangled. The intent is that any new backend gets the entire matrix for free, and that any breakage of the cross-backend contract surfaces as a failed subtest with a stable name.

## Contents

- [Entities](#entities)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `Factory` | type | `func(t *testing.T) keys.KeyStorage` — backend-specific fresh-store constructor passed in by callers. | Per-subtest isolation without coupling the suite to any backend's constructor or cleanup. |
| `RunAll` | func | Registers every `Test*` helper as a named `t.Run` subtest against the supplied `Factory`. | Single entry point so a backend's `_test.go` opts into the full conformance matrix with one line. |
| `TestRegisterAndGet` | func | Puts an HS256 secret, reads it back, asserts byte equality and `Algorithm == "HS256"`. | Smoke test for the most basic Put/Get round-trip every backend must satisfy. |
| `TestNotFound` | func | `GetKey` on an unknown client must return `keys.ErrKeyNotFound` (compared with `==`, not wrapped). | Pins the sentinel error contract callers rely on for branchless miss handling. |
| `TestMultipleHosts` | func | Verifies two distinct `ClientID`s hold distinct key material with no cross-talk. | Catches backends that accidentally namespace-collapse or share a single bucket. |
| `TestDeleteKey` | func | Put, delete, then assert subsequent `GetKey` returns `ErrKeyNotFound`. | Ensures delete is observable to readers, not just locally cached. |
| `TestDeleteNonexistent` | func | Deleting an unknown `ClientID` must return `ErrKeyNotFound`, not nil. | Forces backends to distinguish "no-op delete" from "successful delete" loudly. |
| `TestOverwriteKey` | func | Re-`PutKey` with the same `ClientID` swaps both key material and algorithm in place (HS256 -> HS512). | Confirms upsert semantics so rotations (algorithm change, key change) are honoured. |
| `TestListKeys` | func | After three Puts, `ListKeyIDs` returns exactly those three `ClientID`s (sorted-compared). | Validates the admin/iteration surface every JWKS-like consumer depends on. |
| `TestListKeysEmpty` | func | `ListKeyIDs` on a fresh store returns a zero-length slice with no error. | Guards against backends that nil-panic, error, or leak a sentinel on the empty case. |
| `TestPersistence` | func | Writes then re-reads through the same handle to prove data survives within a process. | Single-process persistence floor; persistent backends satisfy it via shared underlying storage. |
| `TestKidResolverBasic` | func | Stores an HS256 secret then resolves it via `GetKeyByKid` using `utils.ComputeKid(secret, "HS256")` as oracle; unknown kid yields `ErrKidNotFound`. | Asserts the kid-index path matches the `ClientID` path for symmetric keys. |
| `TestKidResolverAsymmetric` | func | Stores an RSA public-key PEM then resolves by kid computed off both PEM bytes and parsed `*rsa.PublicKey`, asserting they match. | Pins the invariant that `ComputeKid(PEM)` equals `ComputeKid(parsedKey)` so backends can index either way. |
| `TestGetCurrentKid` | func | `GetKey` must populate `KeyRecord.Kid` with the canonical thumbprint; miss must return `ErrKeyNotFound`. | Callers stamp JWT headers from `rec.Kid` — backends that forget to fill it would break signing silently. |
| `TestRegisterAndGetAsymmetricKey` | func | Round-trips an RSA public-key PEM through `PutKey`/`GetKey` and decodes it back via `utils.DecodeVerifyKey` into a `*rsa.PublicKey`. | Guards the PEM-as-bytes contract so storage layers don't mangle or re-encode key material. |

## Gotchas

- **`Factory` is called once per subtest, not once per suite.** `RunAll` invokes `factory(t)` inside each `t.Run`, so a backend that returns the same handle every call gets shared state across subtests; a backend that returns a fresh handle gets isolation. `TestPersistence` only passes because the factory hands back a handle whose underlying storage outlives the call — file/DB/GAE backends must point all returned handles at the same path/connection, while inmem backends trivially satisfy this by sharing the same map.
- **`ErrKeyNotFound` vs `ErrKidNotFound` are distinct sentinels.** `GetKey` misses must surface `keys.ErrKeyNotFound`, `GetKeyByKid` misses must surface `keys.ErrKidNotFound`. `==` comparison is used (not `errors.Is`), so backends that wrap the error will fail these tests by design.
- **`DeleteKey` on an absent ClientID is *not* a no-op.** It must return `ErrKeyNotFound`. Backends modelled on `map[string]X` with a plain `delete()` will accidentally pass nil-return semantics and fail `TestDeleteNonexistent`.
- **`PutKey` is upsert.** `TestOverwriteKey` requires that re-putting the same `ClientID` replaces both `Key` and `Algorithm`. Append-only or first-write-wins storage is not a valid backend.
- **`KeyRecord.Key` is `any`, but every backend in scope round-trips it as `[]byte`.** Subtests do `rec.Key.([]byte)` directly; a backend that returns an already-parsed `*rsa.PublicKey` or a re-encoded canonical PEM will fail the assertion. For RS256 the bytes are expected to be the PEM exactly as originally written.
- **`KeyRecord.Kid` is computed by the backend on write, surfaced on read.** `TestGetCurrentKid` asserts `rec.Kid == utils.ComputeKid(secret, alg)`. Backends must either persist the kid alongside the record or recompute it on `GetKey` using the same `utils.ComputeKid` algorithm — otherwise JWT headers stamped from `rec.Kid` won't match what the JWKS endpoint advertises.
- **`ComputeKid(PEM)` must equal `ComputeKid(parsedKey)` for RSA.** `TestKidResolverAsymmetric` explicitly asserts this; it's a contract of `utils.ComputeKid`, but the test pins it here because a drift would silently break kid lookups for asymmetric backends.
- **No encryption-at-rest assertions live here.** This suite covers the plain `keys.KeyStorage` contract; the `EncryptedKeyStorage` wrapper has its own coverage elsewhere. A backend can pass this suite while still leaking secrets at rest.

## Depends on

- `../keys` — Suite is parametrised over `keys.KeyStorage`; uses `keys.KeyRecord` for every Put/Get and pins `keys.ErrKeyNotFound` / `keys.ErrKidNotFound` as the exact sentinels backends must return.
- `../utils` — `utils.ComputeKid` is the oracle for `TestKidResolverBasic` / `TestKidResolverAsymmetric` / `TestGetCurrentKid`; `utils.GenerateRSAKeyPair` and `utils.DecodeVerifyKey` drive the RSA PEM round-trip in `TestRegisterAndGetAsymmetricKey`.
