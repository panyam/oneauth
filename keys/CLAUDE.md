# keys — key storage gotchas

- **JWKS only exposes asymmetric keys.** HS256 secrets are correctly omitted (`jwks_handler.go`). Anything validating via `JWKSKeyStore` must mint RS256/ES256 tokens.
- **`EncryptedKeyStorage` refuses plaintext secrets.** A record that won't decrypt is `ErrKeyDecrypt`, including a plaintext HMAC secret or private PEM. Tests writing to the inner store and reading through the wrapper need `AllowLegacyPlaintext`; a deployment turning encryption on over existing keys starts once with `key_store.migrate_legacy: true` (`KEYSTORE_MIGRATE_LEGACY=true`).
- **`Sealer` purpose labels are fixed by stored data.** `KeyStorePurpose` must never change; a new consumer gets its own label (issue #467).
- **A rotation's grace period needs a KidStore on both sides.** `AppRegistrar.KidStore` keeps the old key and `OneAuthConfig.KidStore` lets the validator find it; with either missing, `grace_period` is accepted and the old key stops verifying at once.
- **RSA keys under 2048 bits fail at load** in `ParsePublicKeyPEM`, `ParsePrivateKeyPEM` and the JWK parser.
