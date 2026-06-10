package apiauth

import (
	"net/http"
	"time"
)

// DeviceFlowMountConfig configures MountDeviceFlow. Mirrors the
// MountASMetadata pattern: the helper owns route placement and handler
// construction; callers supply dependencies + the host-specific
// integration points (session lookup, CSRF token source, optional
// middleware wrapping the verifier routes).
//
// A minimal valid configuration sets APIAuth (with DeviceAuthStore
// populated), VerificationURI, SubjectFromRequest, and
// CSRFTokenFromRequest. Everything else has sensible defaults — the
// helper deliberately keeps the knob count low so the reference server
// and tests both reach for it instead of hand-wiring the four routes.
type DeviceFlowMountConfig struct {
	// APIAuth is the source of DeviceAuthStore (required for the
	// device-grant handler and the verification UI), AppStore (used by
	// the consent screen to render client_name and by the token
	// endpoint to enforce RFC 8628 §3.4 confidential-client auth per
	// issue 266), and the Approve / Deny helpers the verifier calls
	// when the user decides. Required.
	APIAuth *APIAuth

	// VerificationURI is the absolute URL the device displays to the
	// user — RFC 8628 §3.2 makes it REQUIRED on the /device/authorize
	// response. Production: <public-base-url>/device. Tests: the
	// httptest.Server URL + /device. The value is echoed verbatim to
	// the device. Required.
	VerificationURI string

	// VerificationURICompleteTemplate, when set, generates the optional
	// RFC 8628 §3.3.1 verification_uri_complete field. The user_code is
	// substituted into "%s". Example: "https://auth.example/device?user_code=%s".
	// Empty omits the field; the device falls back to verification_uri
	// and prompts the user to type the code.
	VerificationURICompleteTemplate string

	// Expiry overrides the RFC 8628 §3.4 recommended 15-minute window.
	// Zero keeps the default.
	Expiry time.Duration

	// Interval overrides the RFC 8628 §3.5 default 5-second polling
	// interval. Zero keeps the default.
	Interval int

	// ClientAuthenticator authenticates clients at POST /device/authorize.
	// Nil accepts any client_id (test-suitable). For deployments that
	// register confidential clients, wire APIAuth's ClientAuthenticator
	// here so the device-authorize call rejects unauthenticated
	// confidential clients before a code is even minted. Confidential-
	// client enforcement on the REDEMPTION path (POST /api/token) is
	// independent and driven by APIAuth.AppStore (issue 266).
	ClientAuthenticator ClientAuthenticator

	// SubjectFromRequest returns the authenticated subject ("" if the
	// user is unauthenticated). The verification UI uses this to decide
	// whether to redirect to login before showing the consent screen.
	// Wire `httpauth.Middleware.GetLoggedInSubject` or a cookie-reading
	// equivalent. Required.
	SubjectFromRequest func(r *http.Request) string

	// CSRFTokenFromRequest returns the per-request CSRF token to embed
	// in the rendered HTML forms (code-entry and consent). Wire
	// `httpauth.CSRFToken`. Required — the consent forms are rendered
	// with a hidden csrf_token input even when CSRF middleware is off
	// at the route level.
	CSRFTokenFromRequest func(r *http.Request) string

	// LoginRedirectURL is where Submit redirects unauthenticated users.
	// Empty defaults to "/auth/login" (the convention used elsewhere
	// in the library).
	LoginRedirectURL string

	// LoginNextParam names the query parameter used to round-trip the
	// post-login return URL. Empty defaults to "next".
	LoginNextParam string

	// Templates overrides the built-in HTML pages (form / consent /
	// done). Nil uses the package defaults — fine for first-light
	// deployments and tests.
	Templates *DeviceTemplates

	// VerifierMiddleware, when non-nil, wraps each of the four
	// /device and /device/approve routes. Production wires
	// `httpauth.CSRFMiddleware.Protect` here so POST submissions are
	// CSRF-protected; tests pass nil because they drive the routes
	// directly and skip CSRF validation. The /device/authorize route
	// is NOT wrapped — it is a machine-to-machine endpoint called by
	// the device, not a browser form, and CSRF does not apply.
	VerifierMiddleware func(http.Handler) http.Handler
}

// MountDeviceFlow stamps the five RFC 8628 routes onto mux:
//
//	POST /device/authorize  — DeviceAuthorizationHandler (machine endpoint, no middleware)
//	GET  /device            — DeviceVerificationHandler.Form    (browser form)
//	POST /device            — DeviceVerificationHandler.Submit  (browser form)
//	GET  /device/approve    — DeviceVerificationHandler.Consent (browser form)
//	POST /device/approve    — DeviceVerificationHandler.Decide  (browser form)
//
// The four /device + /device/approve routes share the same backing
// DeviceVerificationHandler and, when cfg.VerifierMiddleware is non-nil,
// are wrapped with it. /device/authorize is intentionally unwrapped —
// it is a device-driven JSON endpoint, not a browser form.
//
// Panics if cfg.APIAuth is nil, cfg.APIAuth.DeviceAuthStore is nil, or
// cfg.VerificationURI is empty — those are programming errors the
// caller cannot meaningfully recover from at request time.
//
// Does NOT advertise device_authorization_endpoint in AS metadata; the
// caller is responsible for that on the ASServerMetadata struct passed
// to MountASMetadata.
func MountDeviceFlow(mux *http.ServeMux, cfg DeviceFlowMountConfig) {
	if cfg.APIAuth == nil {
		panic("apiauth: MountDeviceFlow: cfg.APIAuth is required")
	}
	if cfg.APIAuth.DeviceAuthStore == nil {
		panic("apiauth: MountDeviceFlow: cfg.APIAuth.DeviceAuthStore is required (RFC 8628 needs persistence)")
	}
	if cfg.VerificationURI == "" {
		panic("apiauth: MountDeviceFlow: cfg.VerificationURI is required (RFC 8628 §3.2)")
	}

	devAuth := &DeviceAuthorizationHandler{
		Store:                           cfg.APIAuth.DeviceAuthStore,
		VerificationURI:                 cfg.VerificationURI,
		VerificationURICompleteTemplate: cfg.VerificationURICompleteTemplate,
		Expiry:                          cfg.Expiry,
		Interval:                        cfg.Interval,
		ClientAuthenticator:             cfg.ClientAuthenticator,
	}
	mux.Handle("POST /device/authorize", devAuth)

	verifier := &DeviceVerificationHandler{
		Store:    cfg.APIAuth.DeviceAuthStore,
		AppStore: cfg.APIAuth.AppStore,
		Approve: func(r *http.Request, userCode, subject string, scopes []string) error {
			return cfg.APIAuth.ApproveDeviceAuthorization(r, userCode, subject, scopes)
		},
		Deny: func(r *http.Request, userCode string) error {
			return cfg.APIAuth.DenyDeviceAuthorization(r, userCode)
		},
		SubjectFromRequest:   cfg.SubjectFromRequest,
		CSRFTokenFromRequest: cfg.CSRFTokenFromRequest,
		LoginRedirectURL:     cfg.LoginRedirectURL,
		LoginNextParam:       cfg.LoginNextParam,
		Templates:            cfg.Templates,
	}

	wrap := cfg.VerifierMiddleware
	if wrap == nil {
		wrap = func(h http.Handler) http.Handler { return h }
	}
	mux.Handle("GET /device", wrap(http.HandlerFunc(verifier.Form)))
	mux.Handle("POST /device", wrap(http.HandlerFunc(verifier.Submit)))
	mux.Handle("GET /device/approve", wrap(http.HandlerFunc(verifier.Consent)))
	mux.Handle("POST /device/approve", wrap(http.HandlerFunc(verifier.Decide)))
}
