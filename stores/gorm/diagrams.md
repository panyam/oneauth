# gorm — Flows

## Refresh token rotation (`RefreshTokenStore.RotateRefreshToken`)

A single DB transaction trades an old refresh token for a new one in the same
family, detecting reuse and expiry before issuing. The raw token value is
returned only in memory; only its SHA-256 hash is persisted.

```mermaid
sequenceDiagram
    participant C as Caller
    participant S as RefreshTokenStore
    participant TX as gorm.Transaction

    C->>S: RotateRefreshToken(oldToken)
    S->>S: oldHash = sha256(oldToken)
    S->>TX: begin
    TX->>TX: First(oldModel WHERE token_hash = oldHash)
    alt not found
        TX-->>S: ErrTokenNotFound
    else found
        alt oldModel.Revoked
            TX-->>S: ErrTokenReused
        else now > ExpiresAt
            TX-->>S: ErrTokenExpired
        else valid
            TX->>TX: Update old {revoked:true, revoked_at:now}
            S->>S: newToken = GenerateSecureToken()
            TX->>TX: Create newModel {hash, family, generation+1, scopes, AuthZ details}
            TX-->>S: commit
        end
    end
    S->>S: newRefreshToken.Token = newTokenValue (in-memory only)
    S-->>C: *core.RefreshToken (or error)
```

Notable: the new token inherits `Family`, `Scopes`, and `AuthorizationDetails`
from the old one and increments `Generation`; revoke-then-create is atomic so a
crash mid-rotation cannot leave two live tokens.

## Username change (`UsernameStore.ChangeUsername`)

Cross-record optimistic concurrency. When the normalized form is unchanged it is
a single versioned update; when it differs it is a delete-then-create across two
rows, guarded by version checks, with best-effort rollback if the new name was
taken in a race.

```mermaid
flowchart TD
    A[ChangeUsername old,new,userID] --> B{oldNorm == newNorm?}
    B -->|yes, case-only change| C[load existing by oldNorm]
    C --> D{owned by userID?}
    D -->|no| E[error: not owned]
    D -->|yes| F[Update WHERE norm=? AND version=?]
    F --> G{RowsAffected == 0?}
    G -->|yes| H[error: concurrent modification, retry]
    G -->|no| I[ok]

    B -->|no, different name| J[load old by oldNorm]
    J --> K{exists and owned by userID?}
    K -->|no| L[error: not found / not owned]
    K -->|yes| M[check newNorm not taken]
    M --> N{new already exists?}
    N -->|yes| O[error: new username taken]
    N -->|no| P[Delete old WHERE norm=? AND version=?]
    P --> Q{RowsAffected == 0?}
    Q -->|yes| H
    Q -->|no| R[Create new reservation]
    R --> S{create failed - race?}
    S -->|yes| T[re-create old row best-effort, error: taken]
    S -->|no| I
```

Notable: there is no enclosing transaction across the delete+create — the
version guards plus the best-effort restore in the race branch are what protect
consistency. `ReserveUsername` follows the same version-guarded pattern for the
initial reservation.
