package apiauth

import (
	"bytes"
	"context"
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
// defaults to fragment, so oneauth doesn't offer it. With a ResponseSigner
// the four JARM modes follow. fragment.jwt is among them even for code,
// since JARM §2.3.2 defines it for every response type.
func (h *AuthorizationHandler) ResponseModesSupported() []string {
	modes := []string{ResponseModeQuery, ResponseModeFormPost}
	if h.Implicit != nil {
		modes = []string{ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost}
	}
	if h.ResponseSigner != nil {
		modes = append(modes, jarmModes...)
	}
	return modes
}

// checkResponseMode validates req.ResponseMode and returns an OAuth error
// code and description, or two empty strings. An unknown or unoffered
// mode is invalid_request. So is query, or query.jwt, for the implicit
// types: Multiple Response Type Encoding Practices §5 forbids query
// encoding for a response that carries tokens, since the URL ends up in
// logs, history and Referer headers. JARM §2.3.1 says the same of
// query.jwt for an unencrypted response.
func (h *AuthorizationHandler) checkResponseMode(req *AuthorizationRequest) (errCode, errDescription string) {
	mode := req.ResponseMode
	if mode == "" {
		return "", ""
	}
	if !slices.Contains(h.ResponseModesSupported(), mode) {
		return "invalid_request", fmt.Sprintf("unsupported response_mode %q (this server accepts %v)", mode, h.ResponseModesSupported())
	}
	if base, _ := splitResponseMode(mode); base == ResponseModeQuery && h.isImplicit(req) {
		return "invalid_request", fmt.Sprintf("response_mode=%s is not allowed for a response_type that returns tokens", mode)
	}
	return "", ""
}

// responseMode is how req's response goes back: the base mode it is
// delivered in, and whether it is signed (JARM). That is the mode the
// client asked for when checkResponseMode accepts it, and otherwise the
// default for its response type, unsigned. Errors use it too, so a request
// refused for its response_mode hears about it in the default mode.
func (h *AuthorizationHandler) responseMode(req *AuthorizationRequest) (mode string, signed bool) {
	if req.ResponseMode != "" {
		if code, _ := h.checkResponseMode(req); code == "" {
			mode, signed = splitResponseMode(req.ResponseMode)
		}
	}
	if mode == "" {
		mode = ResponseModeQuery
		if h.isImplicit(req) {
			mode = ResponseModeFragment
		}
	}
	return mode, signed
}

// AuthorizationResponse is an authorization response before delivery:
// the parameters, where they go, and how. The verification handler
// redirects for query and fragment, and renders a self-submitting form
// for form_post.
type AuthorizationResponse struct {
	// RedirectURI is the client's checked redirect_uri.
	RedirectURI string

	// Mode is how the parameters are delivered: ResponseModeQuery,
	// ResponseModeFragment or ResponseModeFormPost. A JARM response has
	// its base mode here, so query.jwt is ResponseModeQuery.
	Mode string

	// Values are the response parameters: code or tokens, or error and
	// error_description, with state and iss. For a JARM response they are
	// what the JWT carries, and Params wraps them.
	Values url.Values

	// Signed reports a JARM response, whose Values go out inside one
	// signed `response` parameter.
	Signed bool

	// sign signs Values for a JARM response.
	sign func(url.Values) (string, error)
}

// Params returns the parameters as delivered. For a JARM response that is
// one `response` parameter, signed now, and an error means the response
// can't be sent at all. Otherwise it is Values.
func (a *AuthorizationResponse) Params() (url.Values, error) {
	if !a.Signed {
		return a.Values, nil
	}
	if a.sign == nil {
		return nil, fmt.Errorf("apiauth: a signed authorization response has no signer")
	}
	jwt, err := a.sign(a.Values)
	if err != nil {
		return nil, err
	}
	return url.Values{"response": {jwt}}, nil
}

// RedirectURL encodes the response into the redirect_uri for the query
// and fragment modes. A form_post response has no redirect URL, since its
// values go in a POST body; RedirectURL returns an error for one, as it
// does when a JARM response can't be signed.
func (a *AuthorizationResponse) RedirectURL() (string, error) {
	if a.Mode == ResponseModeFormPost {
		return "", fmt.Errorf("apiauth: a form_post response has no redirect URL; render it with the FormPost template")
	}
	params, err := a.Params()
	if err != nil {
		return "", err
	}
	return a.redirectURL(params)
}

func (a *AuthorizationResponse) redirectURL(params url.Values) (string, error) {
	if a.Mode == ResponseModeFragment {
		return appendFragment(a.RedirectURI, params)
	}
	return appendQuery(a.RedirectURI, params)
}

// newResponse adds state and RFC 9207 iss to values, applies
// RedirectOverride, and picks the response mode for req. A JARM response
// leaves iss out of values, since the JWT's own iss claim carries it.
func (h *AuthorizationHandler) newResponse(req *AuthorizationRequest, values url.Values) *AuthorizationResponse {
	mode, signed := h.responseMode(req)
	if req.State != "" {
		values.Set("state", req.State)
	}
	if h.EmitIssParameter && h.IssuerURL != "" && !signed {
		values.Set("iss", h.IssuerURL)
	}
	if h.RedirectOverride != nil {
		h.RedirectOverride(values)
	}
	resp := &AuthorizationResponse{RedirectURI: req.RedirectURI, Mode: mode, Values: values, Signed: signed}
	if signed && h.ResponseSigner != nil {
		signer, clientID := h.ResponseSigner, req.ClientID
		resp.sign = func(params url.Values) (string, error) {
			out, err := signer.SignAuthorizationResponse(context.Background(), &SignAuthorizationResponseRequest{ClientID: clientID, Params: params})
			if err != nil {
				return "", err
			}
			return out.Response, nil
		}
	}
	return resp
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
// params to resp's redirect_uri, submitted by a script, with a button
// inside <noscript> for a browser without one.
//
// The page carries a code or tokens, so it is no-store and refuses
// framing, and sends no Referer. It replaces any Content-Security-Policy
// already on the response with one that allows only a script or style
// carrying this response's nonce, so it works under a 'self'-only policy
// without 'unsafe-inline'. The policy has no form-action: browsers apply
// it to redirects that follow the POST, and the client may redirect from
// its callback (issue 497).
func (h *AuthorizeVerificationHandler) writeFormPost(w http.ResponseWriter, resp *AuthorizationResponse, params url.Values) {
	nonce, err := cspNonce()
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	data := authorizeFormPostData{RedirectURI: resp.RedirectURI, CSPNonce: nonce}
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, v := range params[name] {
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
