package apiauth

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// AuthorizeMountConfig configures MountAuthorize. Mirrors the
// MountDeviceFlow pattern: the helper owns route placement and
// handler construction; callers supply dependencies + the
// host-specific integration points (session lookup, CSRF token source,
// optional middleware wrapping the browser routes).
//
// A minimal valid configuration sets APIAuth (with AuthorizationCodeStore
// populated), IssuerURL, SubjectFromRequest, and CSRFTokenFromRequest.
// Everything else has sensible defaults — the helper deliberately
// keeps the knob count low so the reference server and tests both
// reach for it instead of hand-wiring the two routes.
type AuthorizeMountConfig struct {
	// OneAuth is the source of AuthorizationCodeStore (required for
	// the authorize handler and the redemption path) and AppStore
	// (used by the consent screen to render client_name and by the
	// handler to validate redirect_uri allowlists). Required.
	OneAuth *OneAuth

	// IssuerURL is the AS's issuer identifier. Echoed on the redirect
	// as `iss` per RFC 9207 when EmitIssParameter is true. Required.
	IssuerURL string

	// EmitIssParameter toggles RFC 9207 `iss` emission on the
	// authorization-response redirect. Pair with
	// ASServerMetadata.AuthorizationResponseIssParameterSupported so
	// the AS's advertisement matches the wire behavior.
	EmitIssParameter bool

	// RedirectURIValidator, when non-nil, overrides AppStore-based
	// (client_id, redirect_uri) validation. See
	// AuthorizationHandler.RedirectURIValidator for details.
	RedirectURIValidator func(ctx context.Context, clientID, redirectURI string) error

	// RedirectOverride, when non-nil, lets conformance scenarios
	// mutate / strip / corrupt the redirect query values before
	// they are encoded. Production deployments leave this nil. See
	// AuthorizationHandler.RedirectOverride.
	RedirectOverride func(values url.Values)

	// Expiry overrides DefaultAuthorizationCodeExpiry. Zero keeps the
	// default.
	Expiry time.Duration

	// SubjectFromRequest returns the authenticated subject ("" if the
	// user is unauthenticated). Wire `httpauth.Middleware.GetLoggedInSubject`
	// or a cookie-reading equivalent. Required.
	SubjectFromRequest func(r *http.Request) string

	// CSRFTokenFromRequest returns the per-request CSRF token to
	// embed in the rendered HTML form. Wire `httpauth.CSRFToken`.
	// Required.
	CSRFTokenFromRequest func(r *http.Request) string

	// LoginRedirectURL is where Consent / Decide redirect
	// unauthenticated users. Empty defaults to "/auth/login".
	LoginRedirectURL string

	// LoginNextParam names the query parameter used to round-trip the
	// post-login return URL. Empty defaults to "next".
	LoginNextParam string

	// Templates overrides the built-in HTML pages. Nil uses the
	// package defaults — fine for first-light deployments and tests.
	Templates *AuthorizeTemplates

	// AutoApproveSubject short-circuits the consent screen for
	// conformance fixtures. Empty disables auto-approve. NEVER set
	// in production deployments.
	AutoApproveSubject string

	// BrowserMiddleware, when non-nil, wraps both /authorize routes.
	// Production wires `httpauth.CSRFMiddleware.Protect` here so POST
	// submissions are CSRF-protected; tests pass nil because they
	// drive the routes directly. The GET path is wrapped too so the
	// CSRF cookie is set on first render.
	BrowserMiddleware func(http.Handler) http.Handler
}

// MountAuthorize stamps the two RFC 6749 §4.1 authorize routes onto
// mux:
//
//	GET  /authorize  → AuthorizeVerificationHandler.Consent (browser form)
//	POST /authorize  → AuthorizeVerificationHandler.Decide  (browser form)
//
// Both routes share the same backing AuthorizeVerificationHandler and,
// when cfg.BrowserMiddleware is non-nil, are wrapped with it.
//
// Panics if cfg.OneAuth is nil, cfg.OneAuth.AuthorizationCodeStore is
// nil, cfg.IssuerURL is empty, or the required function fields are
// nil — those are programming errors the caller cannot meaningfully
// recover from at request time.
//
// Does NOT advertise authorization_endpoint, response_types_supported,
// or code_challenge_methods_supported in AS metadata — the caller
// supplies those on the ASServerMetadata struct passed to
// MountASMetadata.
func MountAuthorize(mux *http.ServeMux, cfg AuthorizeMountConfig) {
	if cfg.OneAuth == nil {
		panic("apiauth: MountAuthorize: cfg.OneAuth is required")
	}
	if cfg.OneAuth.AuthorizationCodeStore == nil {
		panic("apiauth: MountAuthorize: cfg.OneAuth.AuthorizationCodeStore is required (RFC 6749 §4.1 needs persistence)")
	}
	if cfg.IssuerURL == "" {
		panic("apiauth: MountAuthorize: cfg.IssuerURL is required (RFC 9207 needs the issuer URL even when EmitIssParameter is off, for future hardening)")
	}
	if cfg.SubjectFromRequest == nil {
		panic("apiauth: MountAuthorize: cfg.SubjectFromRequest is required")
	}
	if cfg.CSRFTokenFromRequest == nil {
		panic("apiauth: MountAuthorize: cfg.CSRFTokenFromRequest is required")
	}

	authzHandler := &AuthorizationHandler{
		Store:                cfg.OneAuth.AuthorizationCodeStore,
		AppStore:             cfg.OneAuth.AppStore,
		RedirectURIValidator: cfg.RedirectURIValidator,
		IssuerURL:            cfg.IssuerURL,
		EmitIssParameter:     cfg.EmitIssParameter,
		RedirectOverride:     cfg.RedirectOverride,
		Expiry:               cfg.Expiry,
		AllowPlainPKCE:       cfg.OneAuth.AllowPlainPKCE,
	}

	verifier := &AuthorizeVerificationHandler{
		Authorization:        authzHandler,
		AppStore:             cfg.OneAuth.AppStore,
		SubjectFromRequest:   cfg.SubjectFromRequest,
		CSRFTokenFromRequest: cfg.CSRFTokenFromRequest,
		LoginRedirectURL:     cfg.LoginRedirectURL,
		LoginNextParam:       cfg.LoginNextParam,
		Templates:            cfg.Templates,
		AutoApproveSubject:   cfg.AutoApproveSubject,
	}

	wrap := cfg.BrowserMiddleware
	if wrap == nil {
		wrap = func(h http.Handler) http.Handler { return h }
	}
	mux.Handle("GET /authorize", wrap(http.HandlerFunc(verifier.Consent)))
	mux.Handle("POST /authorize", wrap(http.HandlerFunc(verifier.Decide)))
}
