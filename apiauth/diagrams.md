# apiauth — Flow Diagrams

Sequence diagrams for the non-trivial interactions in this package. Generated
by `/design-rebuild-go`; regenerate rather than hand-editing.

### Token endpoint grant dispatch (POST /api/token)

`APIAuth.ServeHTTP` parses the body (form or JSON) and dispatches on
`grant_type`. Each grant validates RFC 9396 `authorization_details` before
minting via `CreateAccessToken`.

```mermaid
flowchart TD
    A[POST /api/token] --> B[ServeHTTP: parse form/JSON into TokenRequest]
    B --> C{grant_type}
    C -->|password| D[handlePasswordGrant]
    C -->|refresh_token| E[handleRefreshTokenGrant]
    C -->|client_credentials| F[handleClientCredentialsGrant]
    C -->|jwt-bearer URN| G[handleJwtBearerGrant]
    C -->|token-exchange URN| H[handleTokenExchangeGrant]
    C -->|other| Z[error: unsupported_grant_type]

    D --> D1[ValidateCredentials] --> D2[GetUserScopes + intersect]
    D2 --> D3[RefreshTokenStore.CreateRefreshToken] --> M[CreateAccessToken] --> R[tokenResponse: access + refresh]

    E --> E1[GetRefreshToken] --> E2{revoked or reused?}
    E2 -->|yes| E3[RevokeTokenFamily + invalid_grant]
    E2 -->|no| E4[RotateRefreshToken] --> M --> R2[tokenResponse: new access + refresh]

    F --> F1[authenticateTokenEndpointClient] --> M2[CreateAccessToken sub=client_id] --> R3[tokenResponse: access only]

    G --> G1[validateAssertion vs TrustedAssertionIssuers] --> M3[CreateAccessToken sub=assertion.sub] --> R4[tokenResponse: access only, no refresh]

    H --> H1{subject_token_type == JWT?} -->|no| Z2[invalid_request]
    H1 -->|yes| H2[validateAssertion] --> M4[CreateAccessToken] --> R5[response incl. issued_token_type]
```

### private_key_jwt client authentication (clientAuthenticator)

The assertion path of `AuthenticateClient`. Parsed once unverified to pick the
issuer/key, then re-parsed under a locked algorithm.

```mermaid
sequenceDiagram
    participant H as Handler (token/introspect/revoke)
    participant E as extractClientCredentials
    participant A as clientAuthenticator
    participant K as keys.KeyLookup
    participant J as JTIStore

    H->>E: extract creds from form/header/req
    E-->>H: AuthenticateClientRequest (assertion path)
    H->>A: AuthenticateClient(req with Audiences)
    A->>A: ParseUnverified -> read iss/sub
    A->>A: require iss==sub (==client_id if form supplied)
    A->>K: GetKey(clientID)
    K-->>A: key record (must be asymmetric alg)
    A->>A: re-Parse with WithValidMethods([rec.Algorithm]) — alg lock
    A->>A: aud matches one of req.Audiences?
    A->>A: exp future, lifetime <= MaxClientAssertionLifetime
    A->>J: SeenWithin(jti, replayWindow)
    J-->>A: false (and atomically marks seen)
    A-->>H: AuthenticateClientResponse{ClientID, Method: private_key_jwt}
```

### Resource-server middleware validation (APIMiddleware)

`validateRequest` tries API key, then local JWT, then remote introspection.

```mermaid
flowchart TD
    A[Incoming request] --> B[validateRequest: read Bearer from header or query]
    B --> C{token prefix oa_ and APIKeyStore set?}
    C -->|yes| D[validateAPIKey -> userID, scopes, api_key]
    C -->|no| E[validateJWT]
    E --> E1{Validator set or buildable from KeyStore?}
    E1 -->|yes| E2[TokenValidator.ValidateToken -> TokenInfo]
    E1 -->|no| E3[validateJWTInline: JWTSecretKey path]
    E2 --> F{ok?}
    E3 --> F
    F -->|yes| G[setAuthContext: userID, scopes, authType, customClaims, authz_details]
    F -->|no, Introspection set| H[IntrospectionValidator.ValidateForMiddleware]
    F -->|no, no fallback| X[handleAuthError 401]
    H --> G
    G --> N[next handler / scope + RFC 9396 gates]
```

### Token revocation (RevocationHandler + tokenRevoker)

```mermaid
sequenceDiagram
    participant C as Caller (client)
    participant H as RevocationHandler
    participant A as ClientAuthenticator
    participant R as tokenRevoker
    participant RS as RefreshTokenStore
    participant BL as TokenBlacklist

    C->>H: POST /oauth/revoke (token, hint, client creds)
    H->>A: AuthenticateClient(creds)
    A-->>H: ok (else 401 invalid_client)
    H->>R: Revoke(token, hint)
    alt hint refresh_token, or empty
        R->>RS: GetRefreshToken + RevokeRefreshToken
    end
    alt hint access_token, or refresh miss on empty hint
        R->>R: ParseUnverified -> jti, exp
        R->>BL: Revoke(jti, exp)
    end
    R-->>H: RevokeResponse (fires TokenHooks.OnRevoked)
    H-->>C: 200 OK (always, per RFC 7009 §2.2)
```
