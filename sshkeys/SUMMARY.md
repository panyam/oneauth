# sshkeys

In-process SSH keypair generation for downstream automation consumers,
packaged in the shapes `oneauth/keys.KeyStorage` and the OpenSSH
ecosystem already consume.

Separate Go submodule (own `go.mod`, mirrors `stores/fs`, `stores/gorm`,
`stores/gae` shape) so it composes opt-in alongside `oneauth/keys`
without pulling its dependency chain into the core import path. Imports
`oneauth/keys` only in tests (for the integration round-trip); the
production helper depends only on `crypto/ed25519`, `encoding/pem`, and
`golang.org/x/crypto/ssh`.

## Public surface

- `GenerateEd25519() (publicAuthorizedKey, privatePEM []byte, err error)`
  — generates a fresh Ed25519 keypair.
  - `publicAuthorizedKey`: single `authorized_keys` line, parseable by
    `ssh.ParseAuthorizedKey`.
  - `privatePEM`: OpenSSH-format PEM block with header
    `OPENSSH PRIVATE KEY`, parseable by `ssh.ParsePrivateKey`.

The private side's PEM header type carries `PRIVATE`, which
`keys.EncryptedKeyStorage` recognizes via its content-driven predicate
— callers can persist the returned PEM directly through `KeyStorage`
and it will be encrypted at rest.

## Out of scope

- RSA / ECDSA SSH key generation. Ed25519 is the modern default; add
  others when there's a real consumer.
- Shelling out to `ssh-keygen`. Filesystem side effects + missing
  binary in container / FaaS environments.
- Cloud KMS integration. Tracked under oneauth issue 9.
- Persisting the JWT issuer signing key. Out of scope per issue 248.
