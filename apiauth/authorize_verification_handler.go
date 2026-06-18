package apiauth

import (
	"html/template"
	"net/http"

	"github.com/panyam/oneauth/core"
)

// AuthorizeVerificationHandler serves the RFC 6749 §4.1 user-facing
// consent flow — the HTML page that bridges between the client's
// /authorize redirect and the AS minting an authorization code. Routes:
//
//	GET  /authorize → Consent  — validates request, shows scope + client name, Approve/Deny buttons
//	POST /authorize → Decide   — applies the decision, redirects back to the client
//
// Validation runs on BOTH methods because a malicious user could
// tamper with the hidden inputs round-tripped through the form. The
// handler keeps apiauth's no-httpauth-import invariant by taking
// session + CSRF lookups as plain functions, mirroring
// DeviceVerificationHandler.
type AuthorizeVerificationHandler struct {
	// Authorization is the parse + validate + IssueCode + redirect
	// engine. Required.
	Authorization *AuthorizationHandler

	// AppStore resolves the client_id to its registered metadata so
	// the consent screen can render the human-readable client_name.
	// Nil renders the raw client_id; never a hard failure. When
	// AuthorizationHandler.AppStore is set this is typically the same
	// store.
	AppStore core.AppRegistrationStore

	// SubjectFromRequest returns the authenticated subject ("" if the
	// user is unauthenticated). Wire `httpauth.Middleware.GetLoggedInSubject`.
	// Required.
	SubjectFromRequest func(r *http.Request) string

	// CSRFTokenFromRequest returns the per-request CSRF token to
	// embed in the rendered form. Wire `httpauth.CSRFToken`. Required.
	CSRFTokenFromRequest func(r *http.Request) string

	// LoginRedirectURL is the URL Consent / Decide redirects
	// unauthenticated users to. The handler appends `?next=<this URL>`
	// so the user returns to the consent screen after logging in.
	// Empty defaults to `/auth/login`.
	LoginRedirectURL string

	// LoginNextParam is the query parameter name used to round-trip
	// the post-login return URL. Empty defaults to `next`.
	LoginNextParam string

	// Templates overrides the built-in HTML pages. Set any subset of
	// fields; nil fields fall back to the package defaults.
	Templates *AuthorizeTemplates

	// AutoApproveSubject, when non-empty, short-circuits the consent
	// screen and approves any well-formed request with this subject.
	// Intended for conformance fixtures and in-process tests — never
	// set this in production deployments. Pairs with
	// testutil.WithAuthorizeAutoApproveSubject.
	AutoApproveSubject string
}

// AuthorizeTemplates lets callers override the built-in HTML pages
// with their own branded versions. Each field is a parsed
// `*template.Template` whose Execute call receives the data shape
// described on the corresponding default constant below.
type AuthorizeTemplates struct {
	// Consent renders GET /authorize. Data: authorizeConsentData.
	Consent *template.Template

	// Error renders the §4.1.2.1 "MUST NOT redirect" error page (bad
	// client_id / redirect_uri). Data: authorizeErrorData.
	Error *template.Template
}

// authorizeConsentData drives the Consent template. ClientID +
// ClientName render the request origin; Scopes render the requested
// permissions; the Hidden fields round-trip the request back through
// the form so Decide can re-validate.
type authorizeConsentData struct {
	ClientID            string
	ClientName          string
	RedirectURI         string
	Scopes              []string
	State               string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
	CSRFToken           string
	ActionURL           string
}

// authorizeErrorData drives the Error template — the page shown to the
// user when client_id / redirect_uri are missing or unregistered (RFC
// 6749 §4.1.2.1 "do not redirect").
type authorizeErrorData struct {
	ErrorCode        string
	ErrorDescription string
}

// Consent serves GET /authorize. Validates the request, decides
// whether to bounce the user to login, and renders the consent screen.
//
// On §4.1.2.1 "display, do not redirect" errors (missing or
// unregistered client_id / redirect_uri) renders an HTML error page.
// On other validation failures redirects to redirect_uri with the
// RFC 6749 §4.1.2.1 error code.
func (h *AuthorizeVerificationHandler) Consent(w http.ResponseWriter, r *http.Request) {
	req, displayErr, errCode, errDescription := h.Authorization.ParseAndValidate(r)
	if errCode != "" {
		if displayErr {
			h.renderError(w, errCode, errDescription)
			return
		}
		h.redirectError(w, r, req, errCode, errDescription)
		return
	}

	// Conformance / test fixture: short-circuit the auth check and
	// the consent screen entirely. NEVER set this in production.
	if h.AutoApproveSubject != "" {
		h.issueAndRedirect(w, r, req, h.AutoApproveSubject)
		return
	}

	subject := h.subject(r)
	if subject == "" {
		// Round-trip the full /authorize URL through the login flow
		// so the user lands back here with their session ready.
		next := r.URL.RequestURI()
		http.Redirect(w, r, loginURLWithNext(h.LoginRedirectURL, h.LoginNextParam, next), http.StatusSeeOther)
		return
	}

	data := authorizeConsentData{
		ClientID:            req.ClientID,
		ClientName:          lookupClientName(r.Context(), h.AppStore, req.ClientID),
		RedirectURI:         req.RedirectURI,
		Scopes:              req.Scopes(),
		State:               req.State,
		ResponseType:        req.ResponseType,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		CSRFToken:           h.csrfToken(r),
		ActionURL:           r.URL.Path,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.consentTemplate().Execute(w, data); err != nil {
		http.Error(w, "render consent", http.StatusInternalServerError)
	}
}

// Decide serves POST /authorize — the user clicked Approve or Deny.
// Re-validates the request (defense against tampered hidden inputs),
// then either redirects with the code (Approve) or with
// `error=access_denied` (Deny). CSRF protection is the caller's
// responsibility — wrap this route with `httpauth.CSRFMiddleware.Protect`.
func (h *AuthorizeVerificationHandler) Decide(w http.ResponseWriter, r *http.Request) {
	req, displayErr, errCode, errDescription := h.Authorization.ParseAndValidate(r)
	if errCode != "" {
		if displayErr {
			h.renderError(w, errCode, errDescription)
			return
		}
		h.redirectError(w, r, req, errCode, errDescription)
		return
	}

	// Auto-approve short-circuits the consent screen for conformance
	// fixtures. NEVER set in production.
	if h.AutoApproveSubject != "" {
		h.issueAndRedirect(w, r, req, h.AutoApproveSubject)
		return
	}

	subject := h.subject(r)
	if subject == "" {
		// Defense in depth — caller should have ensured auth before
		// Decide ran. Bounce to login.
		next := r.URL.Path + "?" + r.URL.RawQuery
		http.Redirect(w, r, loginURLWithNext(h.LoginRedirectURL, h.LoginNextParam, next), http.StatusSeeOther)
		return
	}

	action := r.FormValue("action")
	if action == "deny" {
		h.redirectError(w, r, req, "access_denied", "the user denied the authorization")
		return
	}

	h.issueAndRedirect(w, r, req, subject)
}

func (h *AuthorizeVerificationHandler) issueAndRedirect(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, subject string) {
	code, err := h.Authorization.IssueCode(r.Context(), req, subject, nil)
	if err != nil {
		h.redirectError(w, r, req, "server_error", "could not issue authorization code")
		return
	}
	redirect, err := h.Authorization.SuccessRedirect(req, code)
	if err != nil {
		h.renderError(w, "server_error", "could not build redirect")
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *AuthorizeVerificationHandler) redirectError(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, errCode, errDescription string) {
	if req == nil || req.RedirectURI == "" {
		h.renderError(w, errCode, errDescription)
		return
	}
	redirect, err := h.Authorization.ErrorRedirect(req, errCode, errDescription)
	if err != nil {
		h.renderError(w, errCode, errDescription)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *AuthorizeVerificationHandler) renderError(w http.ResponseWriter, errCode, errDescription string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = h.errorTemplate().Execute(w, authorizeErrorData{
		ErrorCode:        errCode,
		ErrorDescription: errDescription,
	})
}

func (h *AuthorizeVerificationHandler) subject(r *http.Request) string {
	if h.SubjectFromRequest == nil {
		return ""
	}
	return h.SubjectFromRequest(r)
}

func (h *AuthorizeVerificationHandler) csrfToken(r *http.Request) string {
	if h.CSRFTokenFromRequest == nil {
		return ""
	}
	return h.CSRFTokenFromRequest(r)
}

func (h *AuthorizeVerificationHandler) consentTemplate() *template.Template {
	if h.Templates != nil && h.Templates.Consent != nil {
		return h.Templates.Consent
	}
	return defaultAuthorizeConsentTmpl
}

func (h *AuthorizeVerificationHandler) errorTemplate() *template.Template {
	if h.Templates != nil && h.Templates.Error != nil {
		return h.Templates.Error
	}
	return defaultAuthorizeErrorTmpl
}

// Built-in templates. Plain HTML — callers wanting branded UI override
// via AuthorizeTemplates.

var defaultAuthorizeConsentTmpl = template.Must(template.New("authorize_consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize {{.ClientName}}</title></head>
<body>
  <h1>Authorize {{.ClientName}}</h1>
  <p>The application <code>{{.ClientName}}</code> ({{.ClientID}}) is requesting access on your behalf.</p>
  <p>It will return you to <code>{{.RedirectURI}}</code> after you approve.</p>
  {{if .Scopes}}
  <p>Scopes requested:</p>
  <ul>
    {{range .Scopes}}<li><code>{{.}}</code></li>{{end}}
  </ul>
  {{else}}
  <p>No scopes requested.</p>
  {{end}}
  <form method="POST" action="{{.ActionURL}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="response_type" value="{{.ResponseType}}">
    <input type="hidden" name="scope" value="{{range $i, $s := .Scopes}}{{if $i}} {{end}}{{$s}}{{end}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </form>
</body></html>`))

var defaultAuthorizeErrorTmpl = template.Must(template.New("authorize_error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorization error</title></head>
<body>
  <h1>Authorization error</h1>
  <p><strong>{{.ErrorCode}}</strong>{{if .ErrorDescription}}: {{.ErrorDescription}}{{end}}</p>
</body></html>`))
