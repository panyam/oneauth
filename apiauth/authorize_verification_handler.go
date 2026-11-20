package apiauth

import (
	"context"
	"errors"
	"html/template"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/httpauth"
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

	// AuthTimeFromRequest returns when the logged-in user authenticated,
	// which becomes the ID token's `auth_time` (OIDC Core §2). The zero
	// time, or a nil function, leaves the claim out. Wire it to whatever
	// the session records at login, such as the session cookie's `iat`.
	AuthTimeFromRequest func(r *http.Request) time.Time

	// AuthContextFromRequest says how the logged-in user authenticated,
	// which becomes the ID token's `acr` and `amr` (OIDC Core §2).
	// acrValues is the client's `acr_values` in preference order; return
	// the first one the login meets, or the login's own class when it
	// meets none (the parameter is a request, not a requirement). Nil
	// leaves both claims out.
	AuthContextFromRequest func(r *http.Request, acrValues []string) AuthContext

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

	// ConsentStore remembers approvals. With it set, Approve records the
	// user's consent for the client, and a later request it covers skips
	// the consent screen, which lets `prompt=none` succeed (OIDC Core
	// §3.1.2.1). `prompt=consent` shows the screen regardless. Nil shows
	// the screen on every request and answers `prompt=none` with
	// consent_required.
	ConsentStore core.ConsentStore

	// ConsentLifetime is how long a remembered approval counts. Zero uses
	// DefaultConsentLifetime.
	ConsentLifetime time.Duration

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

	// FormPost renders a response_mode=form_post response: a form that
	// POSTs the response to the client's redirect_uri. Data:
	// authorizeFormPostData. The page is served under a nonce-only
	// Content-Security-Policy, so its script needs
	// nonce="{{.CSPNonce}}". It should keep a <noscript> submit button.
	FormPost *template.Template
}

// authorizeConsentData drives the Consent template. ClientID +
// ClientName render the request origin; Scopes render the requested
// permissions; the Hidden fields round-trip the request back through
// the form so Decide can re-validate.
type authorizeConsentData struct {
	ClientID   string
	ClientName string
	// LogoURI, PolicyURI and TOSURI are the client's registered display
	// metadata (OIDC Registration §2), each an https URL or empty. A
	// custom template should show them, so the user sees who is asking.
	LogoURI      string
	PolicyURI    string
	TOSURI       string
	RedirectURI  string
	Scopes       []string
	State        string
	ResponseType string
	// ResponseMode round-trips the `response_mode` parameter, so Approve
	// and Deny answer in the mode the client asked for. Custom consent
	// templates must post it back too.
	ResponseMode        string
	CodeChallenge       string
	CodeChallengeMethod string
	DPoPJKT             string
	Nonce               string
	// Claims round-trips the OIDC `claims` parameter, so Approve issues a
	// code that still carries it. Custom consent templates must post it
	// back too.
	Claims string
	// ACRValues round-trips the OIDC `acr_values` parameter, space
	// separated, so AuthContextFromRequest still sees it at Approve.
	// Custom consent templates must post it back too.
	ACRValues string
	// Resources round-trips the RFC 8707 resource parameters, so Approve
	// issues a code for them. Custom consent templates must post them back
	// too, one hidden input each.
	Resources []string
	// RequestURI round-trips a pushed request (RFC 9126) through the
	// form, so Approve resolves the stored payload instead of re-reading
	// the other hidden inputs as a fresh request. Custom consent
	// templates must post it back too.
	RequestURI string
	CSRFToken  string
	ActionURL  string
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
			h.renderError(w, r, errCode, errDescription)
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

	// OIDC Core §3.1.2.1: prompt=none must not show any page, so each
	// place that would show one answers with an error instead.
	subject := h.subject(r)
	if subject == "" {
		if req.HasPrompt("none") {
			h.redirectError(w, r, req, "login_required", "the user is not logged in")
			return
		}
		h.redirectToLogin(w, r, req)
		return
	}
	if h.needsLogin(r, req) {
		if req.HasPrompt("none") {
			h.redirectError(w, r, req, "login_required", "the request needs a more recent login")
			return
		}
		h.redirectToLogin(w, r, req)
		return
	}
	if !req.HasPrompt("consent") && h.consentRemembered(r.Context(), subject, req) {
		h.issueAndRedirect(w, r, req, subject)
		return
	}
	if req.HasPrompt("none") {
		h.redirectError(w, r, req, "consent_required", "the user has not approved this client for these scopes")
		return
	}

	data := authorizeConsentData{
		ClientID:            req.ClientID,
		ClientName:          lookupClientName(r.Context(), h.AppStore, req.ClientID),
		RedirectURI:         req.RedirectURI,
		Scopes:              req.Scopes(),
		State:               req.State,
		ResponseType:        req.ResponseType,
		ResponseMode:        req.ResponseMode,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		DPoPJKT:             req.DPoPJKT,
		Nonce:               req.Nonce,
		Claims:              req.Claims,
		ACRValues:           strings.Join(req.ACRValues, " "),
		Resources:           req.Resources,
		RequestURI:          req.RequestURI,
		CSRFToken:           h.csrfToken(r),
		ActionURL:           r.URL.Path,
	}
	data.LogoURI, data.PolicyURI, data.TOSURI = lookupClientDisplayURIs(r.Context(), h.AppStore, req.ClientID)
	httpauth.DenyFraming(w)
	if data.LogoURI != "" {
		allowImageOrigin(w.Header(), data.LogoURI)
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
			h.renderError(w, r, errCode, errDescription)
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

	h.rememberConsent(r.Context(), subject, req)
	h.issueAndRedirect(w, r, req, subject)
}

// loginAfterParam carries, in the return URL of a login the handler
// forced, the unix time it forced it. A session that started at or after
// that time satisfies prompt=login and max_age, which is what stops the
// handler sending the user round the login page again. The user can edit
// it, but only to skip their own re-login; the ID token's auth_time still
// reports when they really logged in, and OIDC Core §3.1.2.1 leaves
// checking it against max_age to the client.
const loginAfterParam = "oa_login_after"

// DefaultConsentLifetime is how long a remembered approval counts when
// ConsentLifetime is zero.
const DefaultConsentLifetime = 30 * 24 * time.Hour

// redirectToLogin sends the browser to the login page, with this
// /authorize URL as the place to come back to. A login forced by
// prompt=login or max_age stamps loginAfterParam on that URL.
func (h *AuthorizeVerificationHandler) redirectToLogin(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) {
	back := *r.URL
	if req.HasPrompt("login") || req.MaxAge != nil {
		q := back.Query()
		q.Set(loginAfterParam, strconv.FormatInt(time.Now().Unix(), 10))
		back.RawQuery = q.Encode()
	}
	http.Redirect(w, r, loginURLWithNext(h.LoginRedirectURL, h.LoginNextParam, back.RequestURI()), http.StatusSeeOther)
}

// needsLogin reports whether prompt=login or max_age asks for a more
// recent login than the session has. Without AuthTimeFromRequest the
// handler can't tell when the user logged in, so it enforces neither
// rather than loop through the login page; the ID token then has no
// auth_time, which tells the client.
func (h *AuthorizeVerificationHandler) needsLogin(r *http.Request, req *AuthorizationRequest) bool {
	if h.AuthTimeFromRequest == nil || (!req.HasPrompt("login") && req.MaxAge == nil) {
		return false
	}
	authTime := h.AuthTimeFromRequest(r)
	if after, err := strconv.ParseInt(r.URL.Query().Get(loginAfterParam), 10, 64); err == nil && !authTime.IsZero() && authTime.Unix() >= after {
		return false
	}
	if req.HasPrompt("login") || authTime.IsZero() {
		return true
	}
	return time.Since(authTime) > time.Duration(*req.MaxAge)*time.Second
}

// consentRemembered reports whether ConsentStore holds an unexpired
// approval from subject that covers every scope the request asks for. A
// store error counts as no approval, so the user sees the consent screen.
func (h *AuthorizeVerificationHandler) consentRemembered(ctx context.Context, subject string, req *AuthorizationRequest) bool {
	if h.ConsentStore == nil {
		return false
	}
	resp, err := h.ConsentStore.GetConsent(ctx, &core.GetConsentRequest{Subject: subject, ClientID: req.ClientID})
	if err != nil {
		if !errors.Is(err, core.ErrConsentNotFound) {
			log.Printf("apiauth: authorize: read consent: %v", err)
		}
		return false
	}
	return resp.Grant.Covers(req.Scopes(), time.Now())
}

// rememberConsent records that subject approved the request's client and
// scopes, keeping any scopes an unexpired earlier approval covered. A
// store error is logged and the approval goes ahead: the user only sees
// the consent screen again next time.
func (h *AuthorizeVerificationHandler) rememberConsent(ctx context.Context, subject string, req *AuthorizationRequest) {
	if h.ConsentStore == nil {
		return
	}
	now := time.Now()
	scopes := req.Scopes()
	if resp, err := h.ConsentStore.GetConsent(ctx, &core.GetConsentRequest{Subject: subject, ClientID: req.ClientID}); err == nil && !resp.Grant.IsExpired(now) {
		for _, s := range resp.Grant.Scopes {
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	}
	lifetime := h.ConsentLifetime
	if lifetime <= 0 {
		lifetime = DefaultConsentLifetime
	}
	_, err := h.ConsentStore.SaveConsent(ctx, &core.SaveConsentRequest{Grant: &core.ConsentGrant{
		Subject: subject, ClientID: req.ClientID, Scopes: scopes,
		GrantedAt: now, ExpiresAt: now.Add(lifetime),
	}})
	if err != nil {
		log.Printf("apiauth: authorize: record consent: %v", err)
	}
}

func (h *AuthorizeVerificationHandler) issueAndRedirect(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, subject string) {
	if h.AuthTimeFromRequest != nil {
		req.AuthTime = h.AuthTimeFromRequest(r)
	}
	if h.AuthContextFromRequest != nil {
		ac := h.AuthContextFromRequest(r, req.ACRValues)
		req.ACR, req.AMR = ac.ACR, ac.AMR
	}
	if h.Authorization.isImplicit(req) {
		resp, err := h.Authorization.ImplicitResponse(r.Context(), req, subject)
		if err != nil {
			log.Printf("apiauth: implicit: %v", err)
			h.redirectError(w, r, req, "server_error", "could not issue the tokens")
			return
		}
		h.respond(w, r, resp, "server_error", "could not build redirect")
		return
	}
	code, err := h.Authorization.IssueCode(r.Context(), req, subject, nil)
	if err != nil {
		h.redirectError(w, r, req, "server_error", "could not issue authorization code")
		return
	}
	h.respond(w, r, h.Authorization.SuccessResponse(req, code), "server_error", "could not build redirect")
}

func (h *AuthorizeVerificationHandler) redirectError(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, errCode, errDescription string) {
	if req == nil || req.RedirectURI == "" {
		h.renderError(w, r, errCode, errDescription)
		return
	}
	h.respond(w, r, h.Authorization.ErrorResponse(req, errCode, errDescription), errCode, errDescription)
}

// respond delivers an authorization response in its mode: a form page for
// form_post, a 302 to the redirect URL otherwise. Either way it is
// no-store, since it carries a code, tokens or state. When the redirect
// URL can't be built, the user sees failCode and failDescription.
func (h *AuthorizeVerificationHandler) respond(w http.ResponseWriter, r *http.Request, resp *AuthorizationResponse, failCode, failDescription string) {
	if resp.Mode == ResponseModeFormPost {
		h.writeFormPost(w, resp)
		return
	}
	redirect, err := resp.RedirectURL()
	if err != nil {
		h.renderError(w, r, failCode, failDescription)
		return
	}
	noStore(w)
	http.Redirect(w, r, redirect, http.StatusFound)
}

// renderError shows a §4.1.2.1 "display, do not redirect" error. A client
// that lists application/json in Accept gets the RFC 6749 §5.2 JSON object
// instead of the page, so a headless client can read the error code.
// Browsers never list application/json, and a custom Error template only
// applies to the HTML response.
func (h *AuthorizeVerificationHandler) renderError(w http.ResponseWriter, r *http.Request, errCode, errDescription string) {
	if acceptsJSON(r) {
		writeOAuthError(w, http.StatusBadRequest, errCode, errDescription)
		return
	}
	httpauth.DenyFraming(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = h.errorTemplate().Execute(w, authorizeErrorData{
		ErrorCode:        errCode,
		ErrorDescription: errDescription,
	})
}

// acceptsJSON reports whether Accept lists application/json with a
// nonzero q. It is a deliberately looser test than full negotiation:
// headless clients list JSON after text/html so that consent pages still
// come back as HTML, and on an error the JSON is what they want.
func acceptsJSON(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		fields := strings.Split(part, ";")
		if !strings.EqualFold(strings.TrimSpace(fields[0]), "application/json") {
			continue
		}
		for _, param := range fields[1:] {
			k, v, _ := strings.Cut(strings.TrimSpace(param), "=")
			if strings.EqualFold(k, "q") {
				if q, err := strconv.ParseFloat(v, 64); err == nil && q == 0 {
					return false
				}
			}
		}
		return true
	}
	return false
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
  {{if .LogoURI}}<img id="client-logo" src="{{.LogoURI}}" alt="{{.ClientName}} logo" width="64" height="64" referrerpolicy="no-referrer">{{end}}
  <h1>Authorize {{.ClientName}}</h1>
  <p>The application <code>{{.ClientName}}</code> ({{.ClientID}}) is requesting access on your behalf.</p>
  {{if or .PolicyURI .TOSURI}}<p>
    {{if .PolicyURI}}<a id="client-policy" href="{{.PolicyURI}}" rel="noopener noreferrer" target="_blank">{{.ClientName}} privacy policy</a>{{end}}
    {{if .TOSURI}}<a id="client-tos" href="{{.TOSURI}}" rel="noopener noreferrer" target="_blank">{{.ClientName}} terms of service</a>{{end}}
  </p>{{end}}
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
    {{if .ResponseMode}}<input type="hidden" name="response_mode" value="{{.ResponseMode}}">{{end}}
    <input type="hidden" name="scope" value="{{range $i, $s := .Scopes}}{{if $i}} {{end}}{{$s}}{{end}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    {{if .DPoPJKT}}<input type="hidden" name="dpop_jkt" value="{{.DPoPJKT}}">{{end}}
    {{if .Nonce}}<input type="hidden" name="nonce" value="{{.Nonce}}">{{end}}
    {{if .Claims}}<input type="hidden" name="claims" value="{{.Claims}}">{{end}}
    {{if .ACRValues}}<input type="hidden" name="acr_values" value="{{.ACRValues}}">{{end}}
    {{range .Resources}}<input type="hidden" name="resource" value="{{.}}">
    {{end}}
    {{if .RequestURI}}<input type="hidden" name="request_uri" value="{{.RequestURI}}">{{end}}
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </form>
</body></html>`))

var defaultAuthorizeErrorTmpl = template.Must(template.New("authorize_error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorization error</title></head>
<body>
  <h1 id="authorize-error">Authorization error</h1>
  <p><strong>{{.ErrorCode}}</strong>{{if .ErrorDescription}}: {{.ErrorDescription}}{{end}}</p>
</body></html>`))
