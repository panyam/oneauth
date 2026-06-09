package apiauth

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/panyam/oneauth/core"
)

// DeviceVerificationHandler serves the RFC 8628 §3.3 user-facing
// verification flow — the four HTML pages that bridge between the
// device polling at /api/token and the user authorizing on a separate
// device. Routes:
//
//	GET  /device         → Form    — code entry form
//	POST /device         → Submit  — verifies user_code, redirects to login or consent
//	GET  /device/approve → Consent — shows client_name + scopes, approve/deny buttons
//	POST /device/approve → Decide  — calls Approve/Deny + renders "return to device" page
//
// The handler keeps apiauth's no-httpauth-import invariant by taking
// session + CSRF lookups as plain functions. Callers wire
// `httpauth.Middleware.GetLoggedInSubject` and `httpauth.CSRFToken`
// into the corresponding fields and mount each route behind the same
// middleware that protects their other login pages.
type DeviceVerificationHandler struct {
	// Store enumerates pending device authorizations by user_code.
	// Required.
	Store core.DeviceAuthorizationStore

	// AppStore resolves the client_id bound to a device authorization
	// to its registered metadata so the consent screen can render the
	// human-readable client_name and scope list. Nil renders the raw
	// client_id; never a hard failure.
	AppStore core.AppRegistrationStore

	// Approve transitions a pending authorization to approved and binds
	// the subject. Wire `APIAuth.ApproveDeviceAuthorization` here.
	Approve func(r *http.Request, userCode, subject string, scopes []string) error

	// Deny transitions a pending authorization to denied. Wire
	// `APIAuth.DenyDeviceAuthorization` here.
	Deny func(r *http.Request, userCode string) error

	// SubjectFromRequest returns the authenticated subject ("" if the
	// user is unauthenticated). Wire `httpauth.Middleware.GetLoggedInSubject`.
	SubjectFromRequest func(r *http.Request) string

	// CSRFTokenFromRequest returns the per-request CSRF token to embed
	// in the rendered form. Wire `httpauth.CSRFToken`.
	CSRFTokenFromRequest func(r *http.Request) string

	// LoginRedirectURL is the URL Submit redirects unauthenticated users
	// to. The handler appends a `?next=<consent_url>` query so the user
	// returns to the consent screen after logging in. Empty defaults to
	// `/auth/login`, the convention used elsewhere in the library.
	LoginRedirectURL string

	// LoginNextParam is the query parameter name used to round-trip the
	// post-login return URL. Empty defaults to `next`.
	LoginNextParam string

	// Templates overrides the built-in HTML templates. Set any subset of
	// fields; nil fields fall back to the package defaults.
	Templates *DeviceTemplates
}

// DeviceTemplates lets callers override any of the three built-in HTML
// pages with their own branded versions. Each field is a parsed
// `*template.Template` whose Execute call receives the data shape
// described on the corresponding default constant below.
type DeviceTemplates struct {
	// Form renders the GET /device code entry page. Data: deviceFormData.
	Form *template.Template

	// Consent renders the GET /device/approve consent screen. Data:
	// deviceConsentData.
	Consent *template.Template

	// Done renders the post-decision "return to your device" page.
	// Data: deviceDoneData.
	Done *template.Template
}

// deviceFormData drives the Form template.
type deviceFormData struct {
	UserCode   string // pre-filled when the user arrived via verification_uri_complete
	CSRFToken  string
	ErrorMsg   string // non-empty when the previous submission failed (unknown code, etc.)
	ActionURL  string // the POST target — defaults to the current path
}

// deviceConsentData drives the Consent template.
type deviceConsentData struct {
	UserCode   string
	ClientID   string
	ClientName string // falls back to ClientID when AppStore lookup fails
	Scopes     []string
	CSRFToken  string
	ActionURL  string
}

// deviceDoneData drives the Done template.
type deviceDoneData struct {
	Approved bool
}

// Form serves GET /device — the code entry page.
func (h *DeviceVerificationHandler) Form(w http.ResponseWriter, r *http.Request) {
	h.renderForm(w, r, "", "")
}

// Submit serves POST /device — verifies the submitted user_code and
// either redirects the user to the login flow (if unauthenticated) or to
// the consent screen.
//
// CSRF protection is the caller's responsibility — wrap this route with
// `httpauth.CSRFMiddleware.Protect` so the token is enforced before this
// method runs.
func (h *DeviceVerificationHandler) Submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderForm(w, r, "", "Invalid form submission")
		return
	}
	rawCode := strings.TrimSpace(r.FormValue("user_code"))
	if rawCode == "" {
		h.renderForm(w, r, "", "Enter the code shown on your device")
		return
	}
	if _, err := h.Store.GetByUserCode(r.Context(), &core.GetByUserCodeRequest{UserCode: rawCode}); err != nil {
		if errors.Is(err, core.ErrDeviceAuthorizationNotFound) {
			h.renderForm(w, r, rawCode, "We couldn't find that code. Check what's shown on your device and try again.")
			return
		}
		h.renderForm(w, r, rawCode, "Something went wrong looking up that code.")
		return
	}

	// Consent URL (relative path with the code) — the page the user
	// lands on after authenticating.
	consentURL := "/device/approve?user_code=" + url.QueryEscape(rawCode)

	subject := h.subject(r)
	if subject == "" {
		loginURL := h.loginURLWithNext(consentURL)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, consentURL, http.StatusSeeOther)
}

// Consent serves GET /device/approve — the consent screen. The user
// MUST be authenticated; mount behind `httpauth.Middleware.EnsureUser`
// (or equivalent) so an unauthenticated user is bounced to login.
func (h *DeviceVerificationHandler) Consent(w http.ResponseWriter, r *http.Request) {
	rawCode := strings.TrimSpace(r.URL.Query().Get("user_code"))
	if rawCode == "" {
		h.renderForm(w, r, "", "Enter the code shown on your device")
		return
	}
	getResp, err := h.Store.GetByUserCode(r.Context(), &core.GetByUserCodeRequest{UserCode: rawCode})
	if err != nil {
		h.renderForm(w, r, rawCode, "That code is no longer valid.")
		return
	}
	auth := getResp.Authorization

	data := deviceConsentData{
		UserCode:  rawCode,
		ClientID:  auth.ClientID,
		Scopes:    auth.Scopes,
		CSRFToken: h.csrfToken(r),
		ActionURL: r.URL.Path,
	}
	data.ClientName = auth.ClientID
	if h.AppStore != nil && auth.ClientID != "" {
		if appResp, lookupErr := h.AppStore.GetApp(r.Context(), &core.GetAppRequest{ClientID: auth.ClientID}); lookupErr == nil && appResp != nil && appResp.App != nil && appResp.App.ClientName != "" {
			data.ClientName = appResp.App.ClientName
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := h.consentTemplate()
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "render consent", http.StatusInternalServerError)
	}
}

// Decide serves POST /device/approve — the user clicked Approve or
// Deny. Wrap with `httpauth.CSRFMiddleware.Protect` AND
// `httpauth.Middleware.EnsureUser`; the handler trusts both have run.
func (h *DeviceVerificationHandler) Decide(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	rawCode := strings.TrimSpace(r.FormValue("user_code"))
	action := strings.TrimSpace(r.FormValue("action"))
	if rawCode == "" || (action != "approve" && action != "deny") {
		http.Error(w, "missing user_code or action", http.StatusBadRequest)
		return
	}

	subject := h.subject(r)
	if subject == "" {
		// Defense in depth — EnsureUser should have caught this.
		http.Redirect(w, r, h.loginURLWithNext("/device/approve?user_code="+url.QueryEscape(rawCode)), http.StatusSeeOther)
		return
	}

	// Re-fetch so the consent screen and the decision see the same
	// scope set (a separate consent-narrowing UI could swap this later).
	getResp, err := h.Store.GetByUserCode(r.Context(), &core.GetByUserCodeRequest{UserCode: rawCode})
	if err != nil {
		h.renderForm(w, r, rawCode, "That code is no longer valid.")
		return
	}
	scopes := getResp.Authorization.Scopes

	if action == "deny" {
		if h.Deny != nil {
			_ = h.Deny(r, rawCode)
		}
		h.renderDone(w, false)
		return
	}
	if h.Approve == nil {
		http.Error(w, "approval not configured", http.StatusInternalServerError)
		return
	}
	if err := h.Approve(r, rawCode, subject, scopes); err != nil {
		http.Error(w, "approve: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.renderDone(w, true)
}

func (h *DeviceVerificationHandler) renderForm(w http.ResponseWriter, r *http.Request, userCode, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := deviceFormData{
		UserCode:  userCode,
		CSRFToken: h.csrfToken(r),
		ErrorMsg:  errMsg,
		ActionURL: r.URL.Path,
	}
	tmpl := h.formTemplate()
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "render form", http.StatusInternalServerError)
	}
}

func (h *DeviceVerificationHandler) renderDone(w http.ResponseWriter, approved bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := deviceDoneData{Approved: approved}
	tmpl := h.doneTemplate()
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "render done", http.StatusInternalServerError)
	}
}

func (h *DeviceVerificationHandler) subject(r *http.Request) string {
	if h.SubjectFromRequest == nil {
		return ""
	}
	return h.SubjectFromRequest(r)
}

func (h *DeviceVerificationHandler) csrfToken(r *http.Request) string {
	if h.CSRFTokenFromRequest == nil {
		return ""
	}
	return h.CSRFTokenFromRequest(r)
}

func (h *DeviceVerificationHandler) loginURLWithNext(next string) string {
	loginURL := h.LoginRedirectURL
	if loginURL == "" {
		loginURL = "/auth/login"
	}
	param := h.LoginNextParam
	if param == "" {
		param = "next"
	}
	sep := "?"
	if strings.Contains(loginURL, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%s%s=%s", loginURL, sep, param, url.QueryEscape(next))
}

func (h *DeviceVerificationHandler) formTemplate() *template.Template {
	if h.Templates != nil && h.Templates.Form != nil {
		return h.Templates.Form
	}
	return defaultDeviceFormTmpl
}

func (h *DeviceVerificationHandler) consentTemplate() *template.Template {
	if h.Templates != nil && h.Templates.Consent != nil {
		return h.Templates.Consent
	}
	return defaultDeviceConsentTmpl
}

func (h *DeviceVerificationHandler) doneTemplate() *template.Template {
	if h.Templates != nil && h.Templates.Done != nil {
		return h.Templates.Done
	}
	return defaultDeviceDoneTmpl
}

// Built-in templates. Plain HTML — callers wanting branded UI override
// via DeviceTemplates. Each template's data shape is documented above.

var defaultDeviceFormTmpl = template.Must(template.New("device_form").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize device</title></head>
<body>
  <h1>Authorize your device</h1>
  <p>Enter the code shown on your device.</p>
  {{if .ErrorMsg}}<p style="color:#c00">{{.ErrorMsg}}</p>{{end}}
  <form method="POST" action="{{.ActionURL}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label>Code <input name="user_code" value="{{.UserCode}}" autofocus autocomplete="off" autocapitalize="characters" inputmode="text" required></label>
    <button type="submit">Continue</button>
  </form>
</body></html>`))

var defaultDeviceConsentTmpl = template.Must(template.New("device_consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize {{.ClientName}}</title></head>
<body>
  <h1>Authorize {{.ClientName}}</h1>
  <p>The application <code>{{.ClientName}}</code> ({{.ClientID}}) is requesting access on your behalf.</p>
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
    <input type="hidden" name="user_code" value="{{.UserCode}}">
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </form>
</body></html>`))

var defaultDeviceDoneTmpl = template.Must(template.New("device_done").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{if .Approved}}Approved{{else}}Denied{{end}}</title></head>
<body>
  {{if .Approved}}
  <h1>Approved</h1>
  <p>You may now return to your device.</p>
  {{else}}
  <h1>Denied</h1>
  <p>The authorization was denied. You may close this window.</p>
  {{end}}
</body></html>`))

