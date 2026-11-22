package apiauth

// response_mode at /authorize (issue 500). A client may ask for its
// authorization response as query parameters, in the fragment, or as an
// HTML form that POSTs the values to its redirect_uri (form_post). The
// form page carries the code or tokens, so it is no-store and can't be
// framed. Its auto-submit script runs under a per-response CSP nonce,
// with no 'unsafe-inline'. Query is refused for the implicit types, since
// it would put tokens in the URL.
//
// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
// See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.16
// See: https://github.com/panyam/oneauth/issues/500

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const formPostIssuer = "https://as.example"

type formPostFixture struct {
	mux *http.ServeMux
}

// newFormPostFixture mounts /authorize and /par with RFC 9207 iss on. The
// client "fp" is public and registered for code and both implicit types.
// autoApprove skips the consent screen; without it the user "alice" is
// logged in and sees it.
func newFormPostFixture(t *testing.T, autoApprove, implicit bool) *formPostFixture {
	t.Helper()
	return newAuthorizeFixture(t, autoApprove, implicit, nil)
}

// newAuthorizeFixture is newFormPostFixture with a hook that adjusts the
// OneAuthConfig before NewOneAuth, and the OneAuth before MountAuthorize.
func newAuthorizeFixture(t *testing.T, autoApprove, implicit bool, adjust func(*OneAuthConfig, *ecdsa.PrivateKey)) *formPostFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	apps := core.NewInMemoryAppStore()
	_, err = apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: "fp", RedirectURIs: []string{"https://app.example/cb"}, TokenEndpointAuthMethod: "none",
		ResponseTypes: []string{"code", "id_token", "id_token token"},
	}})
	require.NoError(t, err)
	oaCfg := OneAuthConfig{
		SigningKey: key, SigningAlg: "ES256", VerifyKey: &key.PublicKey, Issuer: formPostIssuer,
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(), AppStore: apps, AllowImplicit: implicit,
		OIDC: &OIDCConfig{},
	}
	if adjust != nil {
		adjust(&oaCfg, key)
	}
	oa := NewOneAuth(oaCfg)
	cfg := AuthorizeMountConfig{
		OneAuth: oa, IssuerURL: formPostIssuer, EmitIssParameter: true,
		SubjectFromRequest:   func(*http.Request) string { return "alice" },
		CSRFTokenFromRequest: func(*http.Request) string { return "csrf" },
		PushedStore:          core.NewInMemoryPushedAuthorizationRequestStore(),
	}
	if autoApprove {
		cfg.AutoApproveSubject = "alice"
	}
	mux := http.NewServeMux()
	MountAuthorize(mux, cfg)
	return &formPostFixture{mux: mux}
}

func formPostQuery(t *testing.T, mode string) url.Values {
	t.Helper()
	_, challenge := pkceFixture(t)
	v := url.Values{
		"client_id": {"fp"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"st-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	if mode != "" {
		v.Set("response_mode", mode)
	}
	return v
}

func (fx *formPostFixture) get(q url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	return rec
}

var (
	formPostInput  = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
	formPostAction = regexp.MustCompile(`<form[^>]*method="post"[^>]*action="([^"]*)"`)
	formPostNonce  = regexp.MustCompile(`<script nonce="([^"]+)">`)
)

// formPostPage checks rec is a form_post page that POSTs to the fixture's
// redirect_uri, with the headers a page carrying a code needs, and
// returns the values it posts.
func formPostPage(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, "want a form_post page, got Location %q body %q", rec.Header().Get("Location"), rec.Body.String())
	assert.Empty(t, rec.Header().Get("Location"))
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"), "the page carries the code (RFC 6749 §5.1 spirit, Form Post §5)")
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"), "the POST shouldn't carry the /authorize URL")
	csp := rec.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.NotContains(t, csp, "unsafe-inline")
	assert.NotContains(t, csp, "form-action", "form-action applies to the client's own redirects after the POST (issue 497)")

	body := rec.Body.String()
	action := formPostAction.FindStringSubmatch(body)
	require.NotNil(t, action, body)
	assert.Equal(t, "https://app.example/cb", html.UnescapeString(action[1]))
	nonce := formPostNonce.FindStringSubmatch(body)
	require.NotNil(t, nonce, "an auto-submit script with a nonce: %s", body)
	assert.Contains(t, csp, "script-src 'nonce-"+html.UnescapeString(nonce[1])+"'", "the script runs under this response's nonce")
	assert.Contains(t, body, "<noscript>", "a submit button for a browser without script")
	assert.Contains(t, body, `type="submit"`)

	values := url.Values{}
	for _, m := range formPostInput.FindAllStringSubmatch(body, -1) {
		values.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return values
}

// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseMode
// See: https://www.rfc-editor.org/rfc/rfc9207#section-2
func TestFormPost_SuccessPostsTheCode(t *testing.T) {
	fx := newFormPostFixture(t, true, false)
	values := formPostPage(t, fx.get(formPostQuery(t, "form_post")))
	assert.NotEmpty(t, values.Get("code"))
	assert.Equal(t, "st-1", values.Get("state"))
	assert.Equal(t, formPostIssuer, values.Get("iss"))
	assert.Len(t, values, 3, "code, state and iss only: %v", values)
}

// Errors after the client and redirect_uri check out go back the same way
// the client asked for its response (Form Post §2).
func TestFormPost_ErrorsArePosted(t *testing.T) {
	fx := newFormPostFixture(t, true, false)
	q := formPostQuery(t, "form_post")
	q.Del("code_challenge")
	values := formPostPage(t, fx.get(q))
	assert.Equal(t, "invalid_request", values.Get("error"))
	assert.NotEmpty(t, values.Get("error_description"))
	assert.Equal(t, "st-1", values.Get("state"))
	assert.Equal(t, formPostIssuer, values.Get("iss"))
	assert.Empty(t, values.Get("code"))
}

// prompt=none answers with an error instead of a page, and that error
// goes back as a form post too.
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func TestFormPost_PromptNoneErrorIsPosted(t *testing.T) {
	fx := newFormPostFixture(t, false, false)
	q := formPostQuery(t, "form_post")
	q.Set("prompt", "none")
	values := formPostPage(t, fx.get(q))
	assert.Equal(t, "consent_required", values.Get("error"))
	assert.Equal(t, "st-1", values.Get("state"))
}

// The consent form carries response_mode through Approve and Deny.
func TestFormPost_ConsentRoundTrip(t *testing.T) {
	fx := newFormPostFixture(t, false, false)
	rec := fx.get(formPostQuery(t, "form_post"))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `name="response_mode" value="form_post"`)

	for action, want := range map[string]string{"approve": "code", "deny": "error"} {
		form := formPostQuery(t, "form_post")
		form.Set("action", action)
		form.Set("csrf_token", "csrf")
		values := formPostPage(t, postForm(fx.mux, form))
		assert.NotEmpty(t, values.Get(want), action)
		assert.Equal(t, "st-1", values.Get("state"), action)
	}
}

// A state that would break out of the attribute is HTML-escaped, and
// posts back byte for byte (CWE-79).
// See: https://cwe.mitre.org/data/definitions/79.html
func TestFormPost_ValuesAreEscaped(t *testing.T) {
	fx := newFormPostFixture(t, true, false)
	q := formPostQuery(t, "form_post")
	state := `"><script>alert(1)</script>&'`
	q.Set("state", state)
	rec := fx.get(q)
	values := formPostPage(t, rec)
	assert.NotContains(t, rec.Body.String(), "<script>alert", "state reached the page unescaped")
	assert.Equal(t, state, values.Get("state"))
}

// An unknown response_mode is a malformed request. The client and
// redirect_uri are good, so the error goes there in the default mode.
// See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
func TestResponseMode_UnknownIsRefused(t *testing.T) {
	fx := newFormPostFixture(t, true, false)
	q := redirectQuery(t, fx.get(formPostQuery(t, "jwt")))
	assert.Equal(t, "invalid_request", q.Get("error"))
	assert.Contains(t, q.Get("error_description"), "response_mode")
	assert.Equal(t, "st-1", q.Get("state"))
	assert.Empty(t, q.Get("code"))
}

// query is the default for code and may be named explicitly.
func TestResponseMode_QueryForCode(t *testing.T) {
	fx := newFormPostFixture(t, true, false)
	q := redirectQuery(t, fx.get(formPostQuery(t, "query")))
	assert.NotEmpty(t, q.Get("code"))
}

// fragment is listed only when the server serves the implicit types.
// With them on, a code request may ask for its code in the fragment;
// without them, the mode is refused.
// See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
func TestResponseMode_FragmentForCode(t *testing.T) {
	on := newFormPostFixture(t, true, true)
	rec := on.get(formPostQuery(t, "fragment"))
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Empty(t, loc.Query())
	frag, err := url.ParseQuery(loc.Fragment)
	require.NoError(t, err)
	assert.NotEmpty(t, frag.Get("code"))
	assert.Equal(t, "st-1", frag.Get("state"))

	off := newFormPostFixture(t, true, false)
	q := redirectQuery(t, off.get(formPostQuery(t, "fragment")))
	assert.Equal(t, "invalid_request", q.Get("error"))
}

func implicitFormPostQuery(responseType, mode string) url.Values {
	return url.Values{
		"client_id": {"fp"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {responseType},
		"scope": {"openid"}, "state": {"st-1"}, "nonce": {"n-1"}, "response_mode": {mode},
	}
}

// response_mode=query with a type that returns tokens would put them in
// the URL, where logs and Referer headers keep them. The spec forbids it,
// so the request is refused, and the error goes in the fragment.
// See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Encoding
func TestResponseMode_QueryRefusedForImplicit(t *testing.T) {
	fx := newFormPostFixture(t, true, true)
	for _, rt := range []string{"id_token", "id_token token"} {
		rec := fx.get(implicitFormPostQuery(rt, "query"))
		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
		loc, err := url.Parse(rec.Header().Get("Location"))
		require.NoError(t, err)
		assert.Empty(t, loc.Query(), "nothing in the query for %s", rt)
		frag, err := url.ParseQuery(loc.Fragment)
		require.NoError(t, err)
		assert.Equal(t, "invalid_request", frag.Get("error"), rt)
		assert.Empty(t, frag.Get("id_token"), rt)
		assert.Equal(t, "st-1", frag.Get("state"), rt)
	}
}

// The implicit types may use form_post: the tokens go as form fields
// (Form Post §2 shows id_token this way).
// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseExample
func TestFormPost_ImplicitPostsTheTokens(t *testing.T) {
	fx := newFormPostFixture(t, true, true)
	values := formPostPage(t, fx.get(implicitFormPostQuery("id_token token", "form_post")))
	assert.NotEmpty(t, values.Get("id_token"))
	assert.NotEmpty(t, values.Get("access_token"))
	assert.Equal(t, "Bearer", values.Get("token_type"))
	assert.Equal(t, "st-1", values.Get("state"))
	assert.Equal(t, formPostIssuer, values.Get("iss"))
}

// A pushed request keeps its response_mode: /authorize reads it from the
// stored payload.
// See: https://www.rfc-editor.org/rfc/rfc9126#section-4
func TestFormPost_ThroughPAR(t *testing.T) {
	fx := newFormPostFixture(t, true, false)
	push := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(formPostQuery(t, "form_post").Encode()))
	push.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, push)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var body struct {
		RequestURI string `json:"request_uri"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	values := formPostPage(t, fx.get(url.Values{"client_id": {"fp"}, "request_uri": {body.RequestURI}}))
	assert.NotEmpty(t, values.Get("code"))
	assert.Equal(t, "st-1", values.Get("state"))

	bad := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(formPostQuery(t, "jwt").Encode()))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, bad)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "PAR validates response_mode like /authorize: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalid_request")
}
