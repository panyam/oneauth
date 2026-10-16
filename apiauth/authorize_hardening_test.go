package apiauth_test

// The authorization endpoint, issue 88's "Input Validation" walk: a pushed
// request survives the consent screen and is spent exactly once, a
// request_uri names its client, PKCE values have the RFC 7636 shape, a
// client gets only its registered scope, and /authorize without a client
// registry refuses rather than redirecting anywhere.
//
// References:
//   - RFC 9126 §4 (https://www.rfc-editor.org/rfc/rfc9126#section-4)
//   - RFC 7636 §4.1, §4.2 (https://www.rfc-editor.org/rfc/rfc7636#section-4.1)
//   - RFC 6749 §3.1.2, §3.3, §4.1.2.1 (https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1)
//   - CWE-601 (https://cwe.mitre.org/data/definitions/601.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// consentRoundTrip renders the consent page for target, then posts its
// hidden inputs back with action=approve, the way a browser does.
func consentRoundTrip(t *testing.T, v *apiauth.AuthorizeVerificationHandler, target string) *httptest.ResponseRecorder {
	t.Helper()
	page := httptest.NewRecorder()
	v.Consent(page, httptest.NewRequest(http.MethodGet, target, nil))
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())

	form := url.Values{"action": {"approve"}}
	for _, m := range hiddenInput.FindAllStringSubmatch(page.Body.String(), -1) {
		form.Set(m[1], strings.ReplaceAll(m[2], "&#43;", "+"))
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	v.Decide(rr, req)
	return rr
}

func consentHandler(authz *apiauth.AuthorizationHandler) *apiauth.AuthorizeVerificationHandler {
	return &apiauth.AuthorizeVerificationHandler{
		Authorization:      authz,
		SubjectFromRequest: func(*http.Request) string { return "alice" },
	}
}

// A pushed request goes through the consent screen and back as a pushed
// request: Approve works when PAR is required, and the reference is spent
// by the first approval, so a replayed form gets no second code.
//
// See: https://www.rfc-editor.org/rfc/rfc9126#section-4
func TestAuthorizeHardening_PushedRequestSurvivesConsentAndIsSpentOnce(t *testing.T) {
	fx := newPARFixture(t)
	fx.authz.RequirePushedRequests = true
	v := consentHandler(fx.authz)
	requestURI := fx.pushOK(t, parForm(nil), "")
	target := "/authorize?client_id=" + parClientID + "&request_uri=" + url.QueryEscape(requestURI)

	first := consentRoundTrip(t, v, target)
	require.Equal(t, http.StatusFound, first.Code, first.Body.String())
	loc, err := url.Parse(first.Header().Get("Location"))
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("code"), "approve with PAR required")

	// The same approval posted again (a double click, a replay).
	form := url.Values{"action": {"approve"}, "client_id": {parClientID}, "request_uri": {requestURI}}
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	again := httptest.NewRecorder()
	v.Decide(again, req)
	assert.NotContains(t, again.Header().Get("Location"), "code=", "a spent request_uri yields no second code")
}

// Two approvals racing on one pushed request: only one gets a code.
//
// See: https://www.rfc-editor.org/rfc/rfc9126#section-4
func TestAuthorizeHardening_PushedRequestIssuesOneCode(t *testing.T) {
	fx := newPARFixture(t)
	requestURI := fx.pushOK(t, parForm(nil), "")
	resolved, errCode, _ := fx.authorize(t, requestURI, parClientID)
	require.Empty(t, errCode)

	_, err := fx.authz.IssueCode(context.Background(), resolved, "alice", nil)
	require.NoError(t, err)
	_, err = fx.authz.IssueCode(context.Background(), resolved, "alice", nil)
	assert.Error(t, err, "the second approval read the request before the first spent it")
}

// See: https://www.rfc-editor.org/rfc/rfc9126#section-4
func TestAuthorizeHardening_RequestURINeedsClientID(t *testing.T) {
	fx := newPARFixture(t)
	requestURI := fx.pushOK(t, parForm(nil), "")
	_, errCode, _ := fx.authorize(t, requestURI, "")
	assert.Equal(t, "invalid_request", errCode)
}

// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.2
func TestAuthorizeHardening_CodeChallengeShape(t *testing.T) {
	fx := newPARFixture(t)
	for name, challenge := range map[string]string{
		"too short":         "abc",
		"not base64url":     strings.Repeat("a", 42) + "=",
		"too long for S256": strings.Repeat("a", 44),
	} {
		req := httptest.NewRequest(http.MethodGet, "/authorize?"+parForm(url.Values{"code_challenge": {challenge}}).Encode(), nil)
		_, _, errCode, _ := fx.authz.ParseAndValidate(req)
		assert.Equal(t, "invalid_request", errCode, name)
	}
}

// A verifier must be 43 to 128 unreserved characters, or a client could
// pick one short enough to guess.
//
// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.1
func TestAuthorizeHardening_CodeVerifierShape(t *testing.T) {
	auth, store := setupAuthCode(t)
	short := "short-verifier"
	_, err := store.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{Code: &core.AuthorizationCode{
		Code: "code-short", ClientID: authcodeTestClientID, RedirectURI: authcodeTestRedirect, Subject: authcodeTestSubject,
		CodeChallenge: core.ComputeCodeChallenge(short), CodeChallengeMethod: core.CodeChallengeMethodS256,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}})
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, url.Values{"code": {"code-short"}, "code_verifier": {short}}))
	assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.3
func TestAuthorizeHardening_RegisteredScopeIsEnforced(t *testing.T) {
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: parClientID, RedirectURIs: []string{parRedirectURI}, Scope: "read",
	}})
	require.NoError(t, err)
	authz := &apiauth.AuthorizationHandler{Store: core.NewInMemoryAuthorizationCodeStore(), AppStore: apps, IssuerURL: "https://as.example.com"}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+parForm(url.Values{"scope": {"read admin"}}).Encode(), nil)
	_, displayErr, errCode, _ := authz.ParseAndValidate(req)
	assert.Equal(t, "invalid_scope", errCode)
	assert.False(t, displayErr, "invalid_scope goes back to the registered redirect_uri")

	req = httptest.NewRequest(http.MethodGet, "/authorize?"+parForm(url.Values{"scope": nil}).Encode(), nil)
	resolved, _, errCode, _ := authz.ParseAndValidate(req)
	require.Empty(t, errCode)
	assert.Equal(t, []string{"read"}, resolved.Scopes(), "no scope asked: the registered default")
}

// With no registry to check redirect_uri against, /authorize would send
// codes wherever the request said. It refuses unless the caller opts in.
//
// See: https://cwe.mitre.org/data/definitions/601.html
func TestAuthorizeHardening_NoRegistryFailsClosed(t *testing.T) {
	authz := &apiauth.AuthorizationHandler{Store: core.NewInMemoryAuthorizationCodeStore(), IssuerURL: "https://as.example.com"}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+parForm(url.Values{"redirect_uri": {"https://attacker.example/cb"}}).Encode(), nil)
	_, displayErr, errCode, _ := authz.ParseAndValidate(req)
	assert.NotEmpty(t, errCode)
	assert.True(t, displayErr, "never redirect to an unchecked redirect_uri")

	authz.AllowAnyRedirectURI = true
	_, _, errCode, _ = authz.ParseAndValidate(req)
	assert.Empty(t, errCode, "explicit opt-in for test fixtures")
}

// The device flow applies the registered scope where the device code is
// issued, since the code carries those scopes to the token.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.1
func TestAuthorizeHardening_DeviceAuthorizationHonorsTheRegisteredScope(t *testing.T) {
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{ClientID: "tv", Scope: "read"}})
	require.NoError(t, err)
	h := &apiauth.DeviceAuthorizationHandler{
		Store:           core.NewInMemoryDeviceAuthorizationStore(),
		VerificationURI: "https://as.example.com/device",
		AppStore:        apps,
	}
	post := func(scope string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/device/authorize", strings.NewReader(url.Values{"client_id": {"tv"}, "scope": {scope}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	assert.Equal(t, http.StatusOK, post("read").Code)
	rr := post("read admin")
	assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid_scope")
}
