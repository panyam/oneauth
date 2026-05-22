# oauth2 — Diagrams

### Authorization-code flow with PKCE (initiation through callback)

Covers `OauthRedirectorWithPKCE` (the `/` route) and a provider's
`handleCallback` (the `/callback/` route). State cookie provides CSRF
protection; PKCE cookie carries the verifier across the round-trip.

```mermaid
sequenceDiagram
    participant U as Browser/User
    participant R as OauthRedirector (/)
    participant CB as Provider handleCallback (/callback/)
    participant P as OAuth Provider (Google/GitHub)
    participant H as HandleUserFunc (host)

    U->>R: GET / (optional ?callbackURL=)
    R->>R: generateStateOauthCookie → "oauthstate"
    R->>R: GenerateCodeVerifier + SetPKCECookie
    R->>R: ComputeCodeChallenge (S256)
    R-->>U: 302 → provider AuthCodeURL(state, code_challenge, S256)
    U->>P: authorize + consent
    P-->>U: 302 → /callback/?code=&state=
    U->>CB: GET /callback/?code=&state=
    CB->>CB: compare state vs "oauthstate" cookie (CSRF)
    alt state mismatch or missing
        CB-->>U: 400 Bad Request
    else state ok
        CB->>CB: GetPKCEVerifier (cookie) + ClearPKCECookie
        CB->>P: Exchange(code, code_verifier) via ExchangeContext
        P-->>CB: oauth2.Token
        CB->>P: getUserData(token) — Bearer header (GitHub) / access_token query (Google)
        P-->>CB: user info JSON
        CB->>H: HandleUserFunc("oauth", provider, token, userInfo, w, r)
        Note over CB,H: on any error → redirect to AuthFailureUrl
    end
```
