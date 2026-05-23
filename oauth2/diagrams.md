# oauth2 — Diagrams

### Authorization-code flow with PKCE (initiation through callback)

The default flow used by both `GoogleOAuth2` and `GithubOAuth2` whenever
`BaseOAuth2.DisablePKCE` is false (its zero value). Covers
`OauthRedirectorWithPKCE` on the `/` route and a provider's
`handleCallback` on the `/callback/` route. The `oauthstate` cookie
provides CSRF protection; the `pkce_verifier` cookie carries the
verifier across the round-trip so no server-side session is needed.

```mermaid
sequenceDiagram
    participant U as Browser/User
    participant R as OauthRedirector (/)
    participant CB as Provider handleCallback (/callback/)
    participant P as OAuth Provider (Google/GitHub)
    participant H as HandleUserFunc (host)

    U->>R: GET / (optional ?callbackURL=)
    R->>R: generateStateOauthCookie -> "oauthstate"
    R->>R: GenerateCodeVerifier + SetPKCECookie
    R->>R: ComputeCodeChallenge (S256)
    R-->>U: 302 -> provider AuthCodeURL(state, code_challenge, S256)
    U->>P: authorize + consent
    P-->>U: 302 -> /callback/?code=&state=
    U->>CB: GET /callback/?code=&state=
    CB->>CB: compare state vs "oauthstate" cookie (CSRF)
    alt state mismatch or missing
        CB-->>U: 400 Bad Request
    else state ok
        CB->>CB: GetPKCEVerifier (cookie) + ClearPKCECookie
        CB->>P: Exchange(code, code_verifier) via ExchangeContext
        P-->>CB: oauth2.Token
        CB->>P: getUserData(token) - Bearer (GitHub) / access_token query (Google)
        P-->>CB: user info JSON
        CB->>H: HandleUserFunc("oauth", provider, token, userInfo, w, r)
        Note over CB,H: on any error -> redirect to AuthFailureUrl
    end
```

### Non-PKCE flow (DisablePKCE=true)

Selected only when a provider rejects PKCE. `NewBaseOAuth2` logs a
startup warning when `DisablePKCE` is true. Same shape as the PKCE flow
minus the verifier/challenge pair, so an attacker who intercepts the
authorization code can redeem it on their own client.

```mermaid
sequenceDiagram
    participant U as Browser/User
    participant R as OauthRedirectorNoPKCE (/)
    participant CB as Provider handleCallback (/callback/)
    participant P as OAuth Provider
    participant H as HandleUserFunc (host)

    U->>R: GET / (optional ?callbackURL=)
    R->>R: generateStateOauthCookie -> "oauthstate"
    R-->>U: 302 -> provider AuthCodeURL(state)
    U->>P: authorize + consent
    P-->>U: 302 -> /callback/?code=&state=
    U->>CB: GET /callback/?code=&state=
    CB->>CB: compare state vs "oauthstate" cookie (CSRF)
    alt state mismatch or missing
        CB-->>U: 400 Bad Request
    else state ok
        CB->>P: Exchange(code) via ExchangeContext
        P-->>CB: oauth2.Token
        CB->>P: getUserData(token)
        P-->>CB: user info JSON
        CB->>H: HandleUserFunc("oauth", provider, token, userInfo, w, r)
        Note over CB,H: on any error -> redirect to AuthFailureUrl
    end
```
