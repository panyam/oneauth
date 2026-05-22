# gae — Flows

## Refresh-token rotation with reuse detection

`RefreshTokenStore.RotateRefreshToken` swaps a presented refresh token for the
next generation in the same family, inside a Datastore transaction. An
already-revoked token is treated as a reuse attack and triggers full-family
revocation (performed outside the transaction, since it spans many entities).

```mermaid
sequenceDiagram
    participant C as Caller
    participant S as RefreshTokenStore
    participant TX as Datastore Txn
    participant DS as Datastore

    C->>S: RotateRefreshToken(oldToken)
    S->>S: oldHash = sha256(oldToken)
    S->>TX: RunInTransaction
    TX->>DS: Get(oldHash)
    alt not found
        DS-->>TX: ErrNoSuchEntity
        TX-->>S: ErrTokenNotFound
    else found & Revoked
        DS-->>TX: entity (Revoked=true)
        TX-->>S: ErrTokenReused
        Note over S: outside txn — revoke whole family
        S->>DS: RevokeTokenFamily(entity.Family)
        S-->>C: nil, ErrTokenReused
    else found & expired
        TX-->>S: ErrTokenExpired
    else valid
        TX->>DS: Put(old: Revoked=true, RevokedAt=now)
        S->>S: generate newToken, newHash
        TX->>DS: Put(new: gen+1, same Family, fresh expiry)
        TX-->>S: commit
        S-->>C: newRefreshToken (raw token + metadata)
    end
```

Key points:

- Tokens are stored under their SHA-256 hash; the raw value never lands in
  Datastore.
- Revoke-old + create-new happen atomically in one transaction so a crash
  cannot leave both live or both dead.
- Family revocation on reuse is deliberately outside the transaction because it
  iterates an unbounded set of entities (`RevokeTokenFamily` runs a query).
