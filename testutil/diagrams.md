# testutil — sequence diagrams

These diagrams show the three multi-step flows in this package: building
a `TestAuthServer`, acquiring a token over HTTP, and minting a JWT
directly without hitting the token endpoint.

## Server construction

`NewTestAuthServer` is a thin shim over `NewAuthServer` that adds
`t.Cleanup`. Construction generates the RSA key, stores it in the
in-memory key store, wires the OAuth handlers into an `httptest.Server`,
and then patches the issuer with the random server URL before mounting
the AS-metadata handler.

```mermaid
sequenceDiagram
    participant Test
    participant testutil
    participant rsa as crypto/rsa
    participant ks as keys.KeyStorage
    participant httptest
    participant apiauth

    Test->>testutil: NewTestAuthServer(t, opts...)
    testutil->>testutil: NewAuthServer(opts...)
    testutil->>testutil: apply Options to config
    testutil->>rsa: GenerateKey(2048)
    rsa-->>testutil: privKey
    testutil->>ks: PutKey(pubPEM, RS256, kid)
    testutil->>apiauth: build APIAuth + introspection + JWKS handler
    testutil->>httptest: NewServer(mux)
    httptest-->>testutil: server.URL (random port)
    testutil->>testutil: if issuer == sentinel, set issuer = server.URL
    testutil->>apiauth: MountASMetadata(mux, ASServerMetadata{...})
    testutil-->>Test: *TestAuthServer
    Test->>testutil: t.Cleanup(s.Close)
```

## Token acquisition over HTTP

The standalone helpers compose into a complete RFC 6749 flow: discover
the AS, POST a grant to the token endpoint, and (optionally) parse the
returned JWT for assertions.

```mermaid
sequenceDiagram
    participant Test
    participant testutil
    participant AS as Authorization Server

    Test->>testutil: DiscoverOIDC(t, issuerURL)
    testutil->>AS: GET /.well-known/openid-configuration
    AS-->>testutil: 200 metadata JSON
    testutil-->>Test: OIDCConfig

    Test->>testutil: GetClientCredentialsToken(t, cfg.TokenEndpoint, id, secret, scopes...)
    testutil->>testutil: PostTokenEndpoint(t, endpoint, form)
    testutil->>AS: POST /api/token (grant_type=client_credentials)
    AS-->>testutil: 200 TokenResponse JSON
    testutil-->>Test: TokenResponse{AccessToken, ...}

    Test->>testutil: ParseJWTClaims(t, AccessToken)
    testutil-->>Test: map[string]any (no signature check)
```

## Direct JWT minting (fast path)

Minting bypasses the HTTP token endpoint entirely. The server signs the
JWT with its in-memory private key and stamps the same `kid` that JWKS
publishes, so consumers can still verify via the standard JWKS path.

```mermaid
sequenceDiagram
    participant Test
    participant TAS as TestAuthServer
    participant jwt as golang-jwt/jwt

    Test->>TAS: MintToken(userID, scopes)
    TAS->>TAS: build standard claims (sub/iss/type/scopes/iat/exp/jti)
    TAS->>TAS: signToken(claims)
    TAS->>jwt: NewWithClaims(RS256, claims)
    TAS->>TAS: ComputeKid(privKey, "RS256")
    TAS->>jwt: set Header["kid"] = kid
    TAS->>jwt: SignedString(privKey)
    jwt-->>TAS: signed RS256 JWT
    TAS-->>Test: tokenString
```

For negative tests, callers use `MintTokenWithClaims` and pre-populate
the claims map with bad values; the defaults loop only fills in
`iss`/`iat`/`exp` when the caller has NOT already set them.
