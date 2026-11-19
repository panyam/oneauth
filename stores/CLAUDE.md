# stores — backend gotchas

- **Documented-contract bar.** Every exported store method documents error-sentinel mapping, idempotency, transactional scope and non-obvious dances. Match `stores/gae/appstore.go` and `keystore.go`, not sparser neighbours.
- **Run the Datastore emulator with `--consistency=1.0`.** At the default 0.9 a query misses a recent write about one time in ten (issue 395). `make upds` / `make testds` pass it and wait for the emulator; CI's `gae` job runs `make testds`. `make downds` first if `testds` turns flaky.
- **A concurrent GORM test on sqlite needs one connection.** Each pooled `:memory:` connection opens its own empty database. Set `SetMaxOpenConns(1)` for sqlite only (see `gorm/refreshtoken_access_tokens_test.go`) and let `make testpg` exercise a real pool.
- **FS identity and channel stores refuse a key whose file holds another key's record** (`fs.ErrKeyCollision`), since file names are lossy. New FS stores name files by a hash of the key (`fsusertoken_store.go`).
- **Custom store contracts.** `AuthorizationCodeStore` needs atomic `ConsumeAuthorizationCode` + `RecordAuthorizationCodeTokens` (issue 429). `RefreshTokenStore` needs `RecordAccessToken` + `RevokeTokenFamily` atomic per record (issue 436, `refreshtokentest.RunAll`). `outbound.UserTokenStore` needs compare-and-swap on `Version` (`usertokentest.RunAll`).
