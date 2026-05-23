// Package oauth2 provides self-contained OAuth2 social-login providers
// (Google, GitHub) with a shared base, PKCE support, and state-cookie CSRF
// protection that hand off the authenticated user to a host-supplied
// HandleUserFunc.
//
// Each provider embeds BaseOAuth2, which holds the client credentials,
// callback URL, an underlying golang.org/x/oauth2 Config, and an
// http.ServeMux. Constructors fall back to OAUTH2_* (and provider-specific
// OAUTH2_GOOGLE_* / OAUTH2_GITHUB_*) environment variables when credentials
// are empty, set the provider endpoint and scopes, and register a
// "/callback/" route alongside the "/" auth-initiation route. The package
// never persists users: when a login succeeds it invokes the caller's
// HandleUserFunc with the provider name, the OAuth token, and the decoded
// user-info map, leaving session and storage concerns to the host. PKCE
// (RFC 7636) is enabled by default — the zero value of DisablePKCE means
// "PKCE on" to satisfy OAuth 2.1 — and DisablePKCE only exists for
// providers that reject it, logging a warning on startup. CSRF is handled
// with a random "oauthstate" cookie compared against the state query
// parameter in the callback. HTTP-client and endpoint setters exist mainly
// as test seams; note that golang.org/x/oauth2 reads the injected client
// off the context, which is why token exchange goes through
// ExchangeContext.
//
// ENTITIES
//
// HandleUserFunc — host-supplied callback receiving (authtype, provider,
// token, userInfo, w, r) on a successful login. Decouples the package
// from any user or session store.
//
// BaseOAuth2 — shared provider state plus the auth-initiation redirect
// handler, embedded by each concrete provider. Centralises credential,
// PKCE, and CSRF wiring.
//
// NewBaseOAuth2 — builds a BaseOAuth2 with env-var credential fallback
// and registers the redirect handler at "/". Called by every concrete
// provider constructor.
//
// BaseOAuth2.Handler — returns the provider's *http.ServeMux for mounting
// under a route prefix. Exposes both "/" and "/callback/".
//
// BaseOAuth2.SetHTTPClient — injects the *http.Client used for user-info
// requests and (via ExchangeContext) token exchange. Test seam; nil falls
// back to http.DefaultClient.
//
// BaseOAuth2.SetOAuthEndpoint — overrides the oauth2.Endpoint (auth and
// token URLs). Test seam for pointing tests at a mock OAuth server.
//
// BaseOAuth2.ExchangeContext — returns a context carrying the injected
// client under the oauth2.HTTPClient key. Required because the exchange
// reads the client off the context, not the struct.
//
// GoogleOAuth2 — Google provider embedding BaseOAuth2. Fetches user info
// passing the access token as a query parameter (Google convention).
//
// NewGoogleOAuth2 — constructs the Google provider with email and profile
// scopes and OAUTH2_GOOGLE_* env fallbacks, registering "/callback/".
//
// GithubOAuth2 — GitHub provider embedding BaseOAuth2. Fetches user info
// with a Bearer Authorization header (GitHub convention).
//
// NewGithubOAuth2 — constructs the GitHub provider with read:user and
// user:email scopes and OAUTH2_GITHUB_* env fallbacks, registering
// "/callback/".
//
// OauthRedirectorWithPKCE — builds the default auth-initiation handler
// that sets state and PKCE cookies and redirects with an S256
// code_challenge. The secure default required by OAuth 2.1.
//
// OauthRedirectorNoPKCE — same initiation without PKCE, selected when
// DisablePKCE is set, for providers lacking PKCE support.
//
// OauthRedirector — convenience wrapper that calls
// OauthRedirectorWithPKCE with secure=false. Back-compat entry point.
//
// GenerateCodeVerifier — produces a 32-byte crypto-random base64url
// verifier (43 chars, the RFC 7636 minimum).
//
// ComputeCodeChallenge — returns BASE64URL(SHA256(verifier)), the S256
// challenge sent on the authorization request.
//
// SetPKCECookie — stores the verifier in an HttpOnly (optionally Secure)
// Lax cookie for the 10-minute flow window. HttpOnly keeps the verifier
// away from JavaScript.
//
// GetPKCEVerifier — reads the verifier cookie in the callback, returning
// "" when absent (which triggers a 400 in the callback handlers).
//
// ClearPKCECookie — expires the verifier cookie after exchange. Verifier
// is single-use and should not survive the flow.
//
// PKCECookieName, PKCECookieTTL, CodeVerifierLength — cookie name,
// 10-minute TTL, and 32-byte verifier length constants shared by the
// PKCE helpers.
//
// FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of: PKCE
// authorization-code login (initiation through callback exchange and
// user delivery) and the legacy non-PKCE variant selected by
// DisablePKCE.
package oauth2
