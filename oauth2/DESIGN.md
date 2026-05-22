---
package: oauth2
purpose: Embeddable OAuth2 authorization-code-flow providers (Google, GitHub) with PKCE and CSRF-state protection, packaged as a standalone Go module decoupled from oneauth core.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: BaseOAuth2
    kind: struct
    role: Shared scaffold holding client credentials, the golang.org/x/oauth2 config, a ServeMux, and the PKCE/cookie toggles that concrete providers embed.
    why: Embedding (not composition) lets Google/GitHub providers inherit the redirect handler and helper methods while only supplying the endpoint, scopes, and callback wiring — keeps provider files tiny.
  - name: GithubOAuth2
    kind: struct
    role: GitHub provider; sets github.Endpoint, read:user/user:email scopes, and fetches user info via Authorization Bearer header.
    why: GitHub requires the access token in an Authorization header (not a query param), so it can't share Google's userinfo fetch path — the divergence is why getUserData isn't on BaseOAuth2.
  - name: GoogleOAuth2
    kind: struct
    role: Google provider; sets google.Endpoint, email/profile scopes, and fetches user info by passing access_token as a query parameter.
    why: Google's userinfo endpoint accepts the token as a query param, the simpler-but-distinct contract from GitHub — justifies per-provider getUserData rather than a shared one.
  - name: HandleUserFunc
    kind: type (func)
    role: Callback signature (authtype, provider, token, userInfo, w, r) the host app supplies to receive an authenticated user after a successful exchange.
    why: Carries provider name and raw userInfo map so the consuming app — not this module — owns session creation and user persistence; keeps the module storage-agnostic and free of oneauth core deps.
  - name: NewBaseOAuth2
    kind: function
    role: Constructor that falls back to OAUTH2_CLIENT_ID/SECRET/CALLBACK_URL env vars when args are empty and wires the root redirect handler.
    why: Env-var fallback supports twelve-factor config without forcing callers to plumb secrets; defaults AuthFailureUrl to /auth/failed so a misconfigured app still fails to a route rather than panicking.
  - name: BaseOAuth2.setupHandlers
    kind: method
    role: Registers the "/" redirect handler, branching to the no-PKCE variant only when DisablePKCE is set (logging a security warning).
    why: PKCE-on is the zero-value default deliberately — OAuth 2.1 mandates it — so forgetting to configure anything yields the secure path; opting out is loud and logged.
  - name: BaseOAuth2.ExchangeContext
    kind: method
    role: Returns a context carrying the injectable HTTPClient under the oauth2.HTTPClient key for the token exchange.
    why: The x/oauth2 library only honors a custom client via context value, not a struct field — this is the seam that makes mock-server testing of the exchange possible.
  - name: BaseOAuth2.SetHTTPClient / SetOAuthEndpoint
    kind: method
    role: Test seams to inject a mock http.Client and point auth/token URLs at a local fake server.
    why: Provider endpoints come from x/oauth2 well-known vars and aren't otherwise overridable; these exist purely so tests don't hit real Google/GitHub.
  - name: GenerateCodeVerifier
    kind: function
    role: Produces a 32-byte crypto-random, base64url-encoded PKCE code_verifier (43 chars).
    why: 32 bytes is chosen because it yields exactly the RFC 7636 minimum length — smaller would be non-compliant, larger is unnecessary.
  - name: ComputeCodeChallenge
    kind: function
    role: Computes the S256 challenge BASE64URL(SHA256(verifier)) sent in the authorization URL.
    why: Only S256 is implemented (no "plain" method) since plain offers no interception protection; hard-coding S256 prevents downgrade.
  - name: SetPKCECookie / GetPKCEVerifier / ClearPKCECookie
    kind: function
    role: Persist, read, and delete the code_verifier in an HttpOnly cookie across the OAuth round-trip.
    why: The verifier must survive the redirect to the provider and back without exposure to JS, hence HttpOnly + SameSite=Lax; the Secure flag is caller-controlled (SecureCookies) so localhost dev over HTTP still works.
  - name: OauthRedirectorWithPKCE
    kind: function
    role: Default "/" handler — mints a state cookie, generates+stores a verifier, and redirects to the provider with code_challenge and code_challenge_method=S256.
    why: Verifier is stashed in a cookie (not server-side session) so the module needs no session store, preserving its zero-dependency, embeddable design.
  - name: OauthRedirectorNoPKCE
    kind: function
    role: Fallback redirect handler that omits the PKCE challenge, used only when DisablePKCE is set.
    why: Exists solely for legacy providers lacking PKCE support; isolating it keeps the insecure path off the default code route.
  - name: OauthRedirector
    kind: function
    role: Back-compat shim that calls OauthRedirectorWithPKCE with secure=false.
    why: Preserves the original single-arg signature for existing callers after PKCE/secure-cookie params were added.
  - name: generateStateOauthCookie
    kind: function
    role: Writes a 16-byte random "oauthstate" cookie returned for embedding in the auth URL.
    why: CSRF defense for the callback — the handler rejects any callback whose state form value doesn't match the cookie, blocking forged authorization responses.
depends_on: []
---

## Provider integration notes

This is a deliberately standalone Go module (`github.com/panyam/oneauth/oauth2`) with its own `go.mod`; it depends on `golang.org/x/oauth2` (plus the `/google` and `/github` endpoint subpackages) but **not** on the oneauth core module. The decoupling means the only contract back to the host app is `HandleUserFunc` plus the raw `userInfo map[string]any` — user persistence, session creation, and token storage all live in the consumer.

**Google vs GitHub divergence.** Both providers share the entire authorization-code + state-validation + PKCE flow via the embedded `BaseOAuth2`. They differ only in (1) the endpoint and scope set chosen in their constructors and (2) how they present the access token to the userinfo endpoint: GitHub uses an `Authorization: Bearer` header, Google passes `access_token` as a URL query parameter. That single transport difference is why `getUserData`/`validateAccessToken` are per-provider rather than hoisted into the base.

**PKCE (RFC 7636).** Enabled by default — the zero value of `DisablePKCE` is the secure path, matching the OAuth 2.1 requirement. The redirect handler generates a `code_verifier`, stores it in an HttpOnly cookie, and sends the S256 `code_challenge`; the callback reads the verifier back, includes it in the token exchange, then clears the cookie. A missing verifier in the callback is treated as an expired/invalid flow and rejected. Only the S256 challenge method is supported (no `plain`).

**Two cookies, two purposes.** `oauthstate` (16 random bytes) is CSRF protection — matched on callback. `pkce_verifier` proves code ownership at exchange time. An optional short-lived `oauthCallbackURL` cookie records where to send the user afterward. `SecureCookies` gates the `Secure` flag on the PKCE/state cookies so HTTP localhost dev works while production can require HTTPS.
