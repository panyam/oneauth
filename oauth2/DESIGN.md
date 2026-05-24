# oauth2

Self-contained OAuth2 social-login providers (Google and GitHub) implemented as a separate Go module (`github.com/panyam/oneauth/oauth2`). Each provider embeds a shared `BaseOAuth2` that owns the credentials, the `oauth2.Config`, an internal mux, and PKCE/state-cookie wiring; the host mounts the provider's `Handler()` under a route prefix, supplies a `HandleUserFunc`, and the package handles authorization-code redirect, S256 PKCE, CSRF state, and userinfo fetch — but never persists users itself.

## Contents

- [Entities](#entities)
- [Flows](#flows)
- [Gotchas](#gotchas)
- [Depends on](#depends-on)

## Entities

| Entity | Kind | Role | Why |
|---|---|---|---|
| `HandleUserFunc` | type | Callback the host supplies to receive `(authtype, provider, token, userInfo, w, r)` on successful login. | Decouples the package from any session/user store. |
| `BaseOAuth2` | struct | Shared provider state: creds, callback URL, `oauth2.Config`, mux, `DisablePKCE`, `SecureCookies`, `HTTPClient`. | Centralises credential, PKCE, and CSRF wiring so providers only add endpoint, scopes, and userinfo. |
| `NewBaseOAuth2` | func | Builds a `BaseOAuth2` with `OAUTH2_*` env fallbacks and wires the redirect handler at `/`. | Env fallback lets deployments configure without code. |
| `BaseOAuth2.Handler` | method | Returns the provider's `*http.ServeMux` for mounting. | Exposes both the `/` initiate route and the provider's `/callback/`. |
| `BaseOAuth2.SetHTTPClient` | method | Injects an `*http.Client` for userinfo and (via context) token exchange. | Test seam for mock servers; nil defaults to `http.DefaultClient`. |
| `BaseOAuth2.SetOAuthEndpoint` | method | Overrides the auth/token URLs on the inner `oauth2.Config`. | Test seam to redirect token exchange to a mock OAuth server. |
| `BaseOAuth2.ExchangeContext` | method | Returns a context carrying the injected HTTP client via the `oauth2.HTTPClient` key. | `golang.org/x/oauth2` reads the client off the context, not the struct. |
| `GoogleOAuth2` | struct | Google provider; embeds `BaseOAuth2` and registers `/callback/`. | Encapsulates Google's endpoint, scopes, and `?access_token=` userinfo convention. |
| `NewGoogleOAuth2` | func | Constructs the Google provider with email/profile scopes. | Uses `OAUTH2_GOOGLE_*` env fallbacks distinct from generic `OAUTH2_*`. |
| `GithubOAuth2` | struct | GitHub provider; embeds `BaseOAuth2` and registers `/callback/`. | Encapsulates GitHub's endpoint, scopes, and Bearer-header userinfo convention. |
| `NewGithubOAuth2` | func | Constructs the GitHub provider with `read:user`/`user:email` scopes. | Uses `OAUTH2_GITHUB_*` env fallbacks. |
| `OauthRedirectorWithPKCE` | func | Initiation handler that sets state + PKCE cookies and redirects with an S256 challenge. | Default initiation path; also stores a `callbackURL` cookie for post-login routing. |
| `OauthRedirectorNoPKCE` | func | Same initiation without PKCE params/cookie. | Used only when `DisablePKCE` is set for providers that reject PKCE. |
| `OauthRedirector` | func | Convenience wrapper for `OauthRedirectorWithPKCE(secure=false)`. | Back-compat default entry point. |
| `GenerateCodeVerifier` | func | Produces a 32-byte crypto-random base64url verifier (43 chars). | 32 bytes is the RFC 7636 §4.1 minimum after encoding. |
| `ComputeCodeChallenge` | func | Returns `BASE64URL(SHA256(verifier))`. | S256 challenge per RFC 7636 §4.2; verifier proves possession at exchange. |
| `SetPKCECookie` | func | Stores the verifier in an HttpOnly (optionally Secure) `SameSite=Lax` cookie. | HttpOnly keeps the verifier away from JS; 10-minute TTL bounds the flow window. |
| `GetPKCEVerifier` | func | Reads the verifier cookie from the callback request, `""` if absent. | Empty result triggers a "verifier missing/expired" 400 in the callback. |
| `ClearPKCECookie` | func | Expires the PKCE verifier cookie after exchange. | Single-use hygiene; verifier must not survive the flow. |
| `PKCECookieName` | const | Cookie name `"pkce_verifier"`. | Shared between set/get/clear helpers. |
| `PKCECookieTTL` | const | Verifier cookie lifetime (10 minutes). | Covers the OAuth round-trip without lingering. |
| `CodeVerifierLength` | const | Verifier byte length (32) before base64. | Yields the RFC-minimum 43-char verifier. |

## Flows

### Authorization-code login with PKCE

```mermaid
sequenceDiagram
    participant U as User Browser
    participant H as Host App (mounts provider.Handler())
    participant R as OauthRedirectorWithPKCE ("/")
    participant P as Provider (Google/GitHub)
    participant C as provider.handleCallback ("/callback/")
    participant Fn as HandleUserFunc

    U->>H: GET /auth/<provider>/?callbackURL=...
    H->>R: dispatch
    R->>R: generate state (oauthstate cookie)
    R->>R: GenerateCodeVerifier + ComputeCodeChallenge(S256)
    R->>U: Set-Cookie: pkce_verifier (HttpOnly, Lax, TTL=10m)
    R->>U: Set-Cookie: oauthstate (TTL=10m)
    R->>U: 302 to P.AuthCodeURL(state, code_challenge, S256)
    U->>P: GET authorize?...
    P->>U: 302 callback?code=...&state=...
    U->>H: GET /auth/<provider>/callback/?code&state (cookies sent)
    H->>C: dispatch
    C->>C: compare r.FormValue("state") vs oauthstate cookie
    alt state mismatch
        C->>U: 400 "invalid oauth state" (clear oauthstate)
    else state ok
        C->>C: GetPKCEVerifier(r) from pkce_verifier cookie
        alt PKCE enabled and verifier missing
            C->>U: 400 "PKCE verifier missing — flow expired"
        else verifier present
            C->>C: ClearPKCECookie(w)
            C->>P: oauthConfig.Exchange(ExchangeContext, code, code_verifier)
            P-->>C: *oauth2.Token (access/refresh)
            C->>P: GET UserInfoURL (Google: ?access_token=; GitHub: Authorization: Bearer)
            P-->>C: userInfo JSON
            C->>Fn: HandleUserFunc("oauth", "<provider>", token, userInfo, w, r)
        end
    end
    alt exchange or userinfo error
        C->>U: 307 redirect to AuthFailureUrl
    end
```

## Gotchas

- **`golang.org/x/oauth2` reads the HTTP client off the context, not the struct.** A bare `oauthConfig.Exchange(context.Background(), ...)` will use `http.DefaultClient` even if you called `SetHTTPClient`. Always go through `BaseOAuth2.ExchangeContext()`, which injects the client under the `oauth2.HTTPClient` context key. Userinfo requests use the client directly via `getHTTPClient()`.

- **PKCE is on by default; disabling logs a runtime warning.** The zero value of `DisablePKCE` is `false`, so providers get S256 PKCE without opt-in (OAuth 2.1 requirement). Setting `DisablePKCE=true` logs a `WARNING` on startup with the client_id and routes initiation through `OauthRedirectorNoPKCE`. Use only when a specific provider rejects PKCE.

- **PKCE verifier lives in a 10-minute HttpOnly cookie.** If the user takes longer than `PKCECookieTTL` on the consent screen, or the cookie was stripped by a privacy mode/cross-site context, the callback returns 400 "verifier missing — flow may have expired". The cookie is `SameSite=Lax` so the provider's top-level redirect carries it; embedded/iframe flows will lose it.

- **`SecureCookies` only affects the PKCE cookie, not the oauthstate cookie.** `generateStateOauthCookie` always sets the state cookie without the Secure flag. Behind a TLS-terminating proxy on HTTPS-only deployments, audit cookie flags before relying on them — the state cookie protects CSRF, so its scope still matters.

- **Provider userinfo conventions differ.** Google takes the access token as `?access_token=` query parameter on `oauth2/v2/userinfo`; GitHub requires `Authorization: Bearer <token>` plus `Accept: application/json` on `/user`. Both `UserInfoURL` fields are public for test override, but a generic switch isn't possible — the call sites differ.

- **Three layers of env-var fallback exist.** Generic `OAUTH2_CLIENT_ID/SECRET/CALLBACK_URL` (in `NewBaseOAuth2`) are overridden by the provider-specific ones (`OAUTH2_GOOGLE_*`, `OAUTH2_GITHUB_*`) when the constructor argument is empty. If you pass an empty string expecting generic env vars, the provider constructor will read its specific vars first and never reach the generic fallback in the base.

- **State-cookie expiry mismatch.** The oauthstate cookie uses `Expires: now+10m` (absolute) while the callbackURL cookie uses `MaxAge: 120` (2 minutes) with a 24h `Expires`. The shorter `MaxAge` wins on compliant browsers, so a slow user can lose the callbackURL even if the state cookie is still valid.

- **Each provider gets its own `http.ServeMux`.** `BaseOAuth2.mux` is private and only reachable via `Handler()`. Two providers must be mounted under distinct route prefixes by the host (e.g., `/auth/google/` and `/auth/github/`) — they cannot share a mux. The `/` and `/callback/` patterns inside each mux are relative to the mount prefix.

- **Separate Go module.** This package has its own `go.mod` and does NOT depend on the parent `oneauth` module. Consumers import it as `github.com/panyam/oneauth/oauth2` independently of the rest of oneauth, and the workspace's `replace` directives handle local dev.

## Depends on

*(none)*
