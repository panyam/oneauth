package apiauth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
)

// Response modes for the authorization response (OAuth 2.0 Multiple
// Response Type Encoding Practices §2.1, and the Form Post Response Mode).
// A client picks one with the `response_mode` parameter. Without it, code
// responses use query and the implicit types use fragment.
const (
	ResponseModeQuery    = "query"
	ResponseModeFragment = "fragment"
	ResponseModeFormPost = "form_post"
)

// ResponseModesSupported lists the response modes h accepts, for AS
// metadata's `response_modes_supported`: query and form_post always, and
// fragment only when h serves the implicit types. Without them nothing
// defaults to fragment, so oneauth doesn't offer it.
func (h *AuthorizationHandler) ResponseModesSupported() []string {
	if h.Implicit != nil {
		return []string{ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost}
	}
	return []string{ResponseModeQuery, ResponseModeFormPost}
}

// checkResponseMode validates req.ResponseMode and returns an OAuth error
// code and description, or two empty strings. An unknown or unoffered
// mode is invalid_request. So is query for the implicit types: Multiple
// Response Type Encoding Practices §5 forbids query encoding for a
// response that carries tokens, since the URL ends up in logs, history
// and Referer headers.
func (h *AuthorizationHandler) checkResponseMode(req *AuthorizationRequest) (errCode, errDescription string) {
	mode := req.ResponseMode
	if mode == "" {
		return "", ""
	}
	if !slices.Contains(h.ResponseModesSupported(), mode) {
		return "invalid_request", fmt.Sprintf("unsupported response_mode %q (this server accepts %v)", mode, h.ResponseModesSupported())
	}
	if mode == ResponseModeQuery && h.isImplicit(req) {
		return "invalid_request", "response_mode=query is not allowed for a response_type that returns tokens"
	}
	return "", ""
}

// responseMode is the mode req's response goes back in: the one the client
// asked for when checkResponseMode accepts it, and otherwise the default
// for its response type. Errors use it too, so a request refused for its
// response_mode hears about it in the default mode.
func (h *AuthorizationHandler) responseMode(req *AuthorizationRequest) string {
	if req.ResponseMode != "" {
		if code, _ := h.checkResponseMode(req); code == "" {
			return req.ResponseMode
		}
	}
	if h.isImplicit(req) {
		return ResponseModeFragment
	}
	return ResponseModeQuery
}

// AuthorizationResponse is an authorization response before delivery:
// the parameters, where they go, and how. The verification handler
// redirects for query and fragment, and renders a self-submitting form
// for form_post.
type AuthorizationResponse struct {
	// RedirectURI is the client's checked redirect_uri.
	RedirectURI string

	// Mode is ResponseModeQuery, ResponseModeFragment or
	// ResponseModeFormPost.
	Mode string

	// Values are the response parameters: code or tokens, or error and
	// error_description, with state and iss.
	Values url.Values
}

// RedirectURL encodes the response into the redirect_uri for the query
// and fragment modes. A form_post response has no redirect URL, since its
// values go in a POST body; RedirectURL returns an error for one.
func (a *AuthorizationResponse) RedirectURL() (string, error) {
	switch a.Mode {
	case ResponseModeFragment:
		return appendFragment(a.RedirectURI, a.Values)
	case ResponseModeFormPost:
		return "", fmt.Errorf("apiauth: a form_post response has no redirect URL; render it with the FormPost template")
	default:
		return appendQuery(a.RedirectURI, a.Values)
	}
}

// newResponse adds state and RFC 9207 iss to values, applies
// RedirectOverride, and picks the response mode for req.
func (h *AuthorizationHandler) newResponse(req *AuthorizationRequest, values url.Values) *AuthorizationResponse {
	if req.State != "" {
		values.Set("state", req.State)
	}
	if h.EmitIssParameter && h.IssuerURL != "" {
		values.Set("iss", h.IssuerURL)
	}
	if h.RedirectOverride != nil {
		h.RedirectOverride(values)
	}
	return &AuthorizationResponse{RedirectURI: req.RedirectURI, Mode: h.responseMode(req), Values: values}
}

// authorizeFormPostData drives the FormPost template. Fields are the
// response parameters in name order. CSPNonce is this response's
// Content-Security-Policy nonce: a custom template's script and style
// elements need nonce="{{.CSPNonce}}", or the browser refuses to run them.
type authorizeFormPostData struct {
	RedirectURI string
	Fields      []authorizeFormField
	CSPNonce    string
}

type authorizeFormField struct {
	Name, Value string
}

// writeFormPost renders a form_post response: an HTML form that POSTs
// resp.Values to the redirect_uri, submitted by a script, with a button
// inside <noscript> for a browser without one.
//
// The page carries a code or tokens, so it is no-store and refuses
// framing, and sends no Referer. It replaces any Content-Security-Policy
// already on the response with one that allows only a script or style
// carrying this response's nonce, so it works under a 'self'-only policy
// without 'unsafe-inline'. The policy has no form-action: browsers apply
// it to redirects that follow the POST, and the client may redirect from
// its callback (issue 497).
func (h *AuthorizeVerificationHandler) writeFormPost(w http.ResponseWriter, resp *AuthorizationResponse) {
	nonce, err := cspNonce()
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	data := authorizeFormPostData{RedirectURI: resp.RedirectURI, CSPNonce: nonce}
	names := make([]string, 0, len(resp.Values))
	for name := range resp.Values {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, v := range resp.Values[name] {
			data.Fields = append(data.Fields, authorizeFormField{Name: name, Value: v})
		}
	}
	var page bytes.Buffer
	if err := h.formPostTemplate().Execute(&page, data); err != nil {
		http.Error(w, "render form_post response", http.StatusInternalServerError)
		return
	}
	hdr := w.Header()
	noStore(w)
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page.Bytes())
}

// cspNonce returns 128 random bits in base64url, for one response's
// Content-Security-Policy nonce. CSP3 asks for at least 128 bits, and
// base64url gives html/template nothing to escape in the nonce attribute.
func cspNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *AuthorizeVerificationHandler) formPostTemplate() *template.Template {
	if h.Templates != nil && h.Templates.FormPost != nil {
		return h.Templates.FormPost
	}
	return defaultAuthorizeFormPostTmpl
}

var defaultAuthorizeFormPostTmpl = template.Must(template.New("authorize_form_post").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Returning to the application</title></head>
<body>
  <form id="authorize-form-post" method="post" action="{{.RedirectURI}}">
    {{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
    {{end}}<noscript><p>Script is turned off. Press Continue to return to the application.</p><button type="submit">Continue</button></noscript>
  </form>
  <script nonce="{{.CSPNonce}}">document.getElementById("authorize-form-post").submit();</script>
</body></html>`))
