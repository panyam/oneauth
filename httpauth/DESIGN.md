---
package: httpauth
purpose: HTTP-layer authentication for browser flows — session/cookie/JWT user-extraction middleware, OAuth callback + account-linking mux, and standalone CSRF, body-limit, and security-header middlewares.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: OneAuth
    kind: struct
    role: Central session-mux orchestrator that owns the OAuth callback flow, JWT minting/verification, multi-domain cookie management, and logout.
    why: Bundles secret/session/issuer config with sensible defaults pulled from env (ONEAUTH_JWT_SECRET_KEY) so a host app gets a working browser-auth surface from `New(appName)`; the hardcoded fallback secret is a test-only convenience that must be overridden in prod.
  - name: AuthUserStore
    kind: interface
    role: Composes core UserStore + IdentityStore + ChannelStore plus EnsureAuthUser, the single entry point that reconciles an OAuth/local identity into a system user.
    why: Keeps OneAuth from depending on three separate store params and centralizes the create-or-lookup decision in one orchestrating method rather than scattering it across callback handlers.
  - name: New
    kind: function
    role: Constructs a OneAuth with defaults applied.
    why: EnsureDefaults is idempotent and re-invoked across the lifecycle, so callers can also build OneAuth as a struct literal and still get safe fallbacks.
  - name: OneAuth.AddAuth
    kind: method
    role: Mounts a provider handler under a prefix with subtree matching, plus a no-slash redirect shim.
    why: Works around net/http StripPrefix yielding an empty path on the bare prefix; uses 308 (not 301) so POST/PUT methods survive the trailing-slash redirect instead of being downgraded to GET.
  - name: OneAuth.SaveUserAndRedirect
    kind: method
    role: Post-OAuth-callback hook — ensures the user, sets login cookies/session, and redirects to the stored callbackURL.
    why: Reads and then immediately expires the `oauthCallbackURL` cookie so a stale callback target can't be reused on later logins; relative callbackURLs are prefixed with OAUTH2_BASE_URL.
  - name: OneAuth.setLoggedInUser
    kind: method
    role: Sets (or clears, when user is nil) the loggedInUserId cookie, the HS256 JWT auth-token cookie, and session vars across every configured cookie domain.
    why: Iterating CookieDomains (always including "" for the default host) is how login/logout propagate across sibling subdomains in one pass; passing a User rather than an ID is a deliberate hook for future profile-in-claims, flagged as possibly unnecessary.
  - name: OneAuth.HandleLinkOAuthCallback
    kind: method
    role: Links an OAuth provider to an existing local-only account, creating/updating the channel and the user's profile channel list.
    why: Enforces that the OAuth-returned email case-insensitively matches the existing account email — the load-bearing guard against account hijacking by linking an attacker-controlled provider identity.
  - name: LinkOAuthConfig
    kind: struct
    role: Bundles the three stores HandleLinkOAuthCallback needs.
    why: Lets the linking flow take only the stores it uses instead of the full AuthUserStore, honoring the no-god-object convention.
  - name: OneAuth.StartLinkOAuth / GetLinkingUserID
    kind: method
    role: Stash/retrieve the linking user ID in session to signal that a callback is a link flow rather than a fresh login.
    why: GetLinkingUserID uses PopString (read-and-delete) so the linking signal is single-use and can't accidentally re-trigger linking on a subsequent normal login.
  - name: Middleware
    kind: struct
    role: Request-scoped user extraction from context, then session, then Authorization header/cookie via a pluggable VerifyToken; provides ExtractUser and EnsureUser handlers.
    why: Resolution order (context > session > token) lets upstream middleware short-circuit verification; VerifyToken is injected to keep JWT specifics out of the middleware (the `// TODO Decouple jwt` note marks this seam).
  - name: Middleware.GetLoggedInUserId
    kind: method
    role: Resolves the current user ID, trying context, SessionGetter, then each auth header/cookie token.
    why: Truncates the token to 20 chars in warn logs to avoid leaking full credentials; returns "" rather than erroring so callers decide whether absence is fatal.
  - name: Middleware.ExtractUser
    kind: method
    role: Non-enforcing middleware that loads the user ID into request context for downstream handlers.
    why: Deliberately never redirects/401s — pairs with EnsureUser, which adds enforcement, so handlers can choose soft vs hard auth.
  - name: Middleware.EnsureUser
    kind: method
    role: Enforcing middleware that redirects to login (or 401s) when no user is resolved.
    why: Redirects only when GetRedirURL is set, otherwise 401s — encodes the callback path with "+"→"%20" fixup so spaces survive the login round-trip.
  - name: CSRFMiddleware
    kind: struct
    role: Double-submit-cookie CSRF protection with configurable cookie/field/header names and an exempt predicate.
    why: The CSRF cookie is intentionally NOT HttpOnly so JS can echo it into the AJAX header; Bearer-token requests are exempt by default because they're not cookie-driven and thus not CSRF-vulnerable.
  - name: CSRFMiddleware.Protect
    kind: method
    role: Issues a token on safe methods (GET/HEAD/OPTIONS) and validates it on unsafe ones.
    why: Compares cookie vs submitted token with crypto/subtle constant-time compare to avoid timing oracles; checks form field before header.
  - name: CSRFToken / CSRFTemplateField
    kind: function
    role: Read the active token from request context / emit it as a hidden HTML form input.
    why: CSRFTemplateField HTML-escapes the token and returns template.HTML so it renders unescaped in templates without opening an injection hole.
  - name: generateCSRFToken
    kind: function
    role: Produces a 32-byte crypto/rand hex token.
    why: Panics on rand failure rather than emitting a weak/empty token — a missing CSRF token is a security failure that must be loud, not silent.
  - name: LimitBody
    kind: function
    role: Middleware that rejects (413) requests whose ContentLength exceeds maxBytes and wraps the body in MaxBytesReader.
    why: The upfront ContentLength check fast-fails declared-oversize bodies, while MaxBytesReader is the safety net for chunked transfers where ContentLength is -1 (CWE-400 defense).
  - name: LimitBodyReader
    kind: function
    role: Lower-level helper to cap a body inside a handler instead of as middleware.
    why: Defers the error to read-time rather than rejecting upfront, for handlers that want per-route limits.
  - name: IsBodyTooLargeError
    kind: function
    role: Detects whether an error came from exceeding a MaxBytesReader limit.
    why: Matches *http.MaxBytesError (Go 1.19+) and falls back to io.ErrUnexpectedEOF so callers can return 413 distinctly from other read errors.
  - name: SecurityHeaders / SecurityHeadersWithConfig
    kind: function
    role: Middleware that sets OWASP-recommended response headers (HSTS, CSP, frame options, COEP/COOP/CORP, etc.).
    why: Every header is suppressible by setting its config field to "" / 0, so a host can relax individual policies (e.g. a permissive CSP) without forking the middleware.
  - name: SecurityHeadersConfig / DefaultSecurityHeadersConfig
    kind: struct
    role: Per-header configuration with a secure-by-default constructor.
    why: Defaults lean strict (DENY frames, default-src 'self', 1yr HSTS with subdomains) so the safe path requires no config; X-Content-Type-Options:nosniff is always set unconditionally.
depends_on:
  - folder: core
    entities: [User, BasicUser, Channel, IdentityKey, UserStore, IdentityStore, ChannelStore]
---

## HTTP middleware

The package is the browser-facing complement to `apiauth` (which handles bearer-token API auth). Two middleware families coexist:

- **User extraction** (`Middleware`): a small, transport-aware resolver that pulls a user ID from request context, session (`SessionGetter`), or an Authorization header/cookie validated through an injected `VerifyToken`. `ExtractUser` is soft (load only), `EnsureUser` is hard (redirect-or-401). JWT details are deliberately injected rather than imported, with a `TODO` marking the remaining coupling.
- **Standalone protective middlewares** (`LimitBody`, `SecurityHeaders`, `CSRFMiddleware`): each is independent and wraps any `http.Handler`, so a host app composes only what it needs.

## CSRF

Implements the double-submit-cookie pattern. Safe methods mint/refresh the cookie and stash the token in context; unsafe methods must echo it back via form field or header, compared in constant time. The cookie is intentionally non-HttpOnly (JS must read it for AJAX), and Bearer-token requests are exempt by default since cookie-less requests aren't CSRF targets. Token generation panics on RNG failure to avoid silently shipping a weak token.

## Session / OAuth mux

`OneAuth` is the stateful core: it owns an `http.ServeMux`, an `scs/v2` session manager, and the OAuth callback lifecycle. `SaveUserAndRedirect` is the post-callback landing point; `setLoggedInUser` writes login/logout cookies and an HS256 JWT across every configured cookie domain in one pass (the `""` default domain is always included). Account linking (`StartLinkOAuth` → `GetLinkingUserID` → `HandleLinkOAuthCallback`) layers on top, gated by an email-match check that is the key anti-hijacking control. Routing quirks worth noting: `AddAuth` mounts under `prefix + "/"` for subtree matching and adds a 308 redirect from the bare prefix so methods aren't downgraded.
