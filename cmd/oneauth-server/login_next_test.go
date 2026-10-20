package main

// The login page returns the user to the page that sent them there. An
// unauthenticated /authorize redirects to /auth/login?next=<the authorize
// URL>; after a successful login the browser goes back to that URL and
// reaches the consent page. Only a path on this site is followed, so the
// login form is never an open redirect.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
// See: https://cwe.mitre.org/data/definitions/601.html
// See: https://github.com/panyam/oneauth/issues/438

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	loginCSRFField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	loginNextField = regexp.MustCompile(`name="next" value="([^"]*)"`)
)

const (
	loginTestEmail    = "next-user@example.com"
	loginTestPassword = "correct-horse-battery-staple"
)

// loginFixture is a reference server built by buildServer from a code-flow
// config, with one signed-up user and one public client registered through
// DCR. Its HTTP client keeps cookies and stops at every redirect.
type loginFixture struct {
	url      string
	http     *http.Client
	clientID string
	redirect string
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()
	return newLoginFixtureWith(t, "")
}

// newLoginFixtureWith appends jwtExtra under the config's jwt block.
func newLoginFixtureWith(t *testing.T, jwtExtra string) *loginFixture {
	t.Helper()
	return newLoginFixtureConfig(t, jwtExtra, "")
}

// newLoginFixtureConfig appends jwtExtra under the jwt block and
// codeFlowExtra under code_flow.
func newLoginFixtureConfig(t *testing.T, jwtExtra, codeFlowExtra string) *loginFixture {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	base := "http://" + srv.Listener.Addr().(*net.TCPAddr).String()
	cfg := loadYAML(t, fmt.Sprintf(`
server:
  public_url: %s
keystore:
  type: memory
user_stores:
  type: memory
jwt:
  secret_key: "login-next-test-secret-32-bytes!"
%s
admin_auth:
  type: none
  allow_open: true
code_flow:
  enabled: true
%s
`, base, jwtExtra, codeFlowExtra))
	handler, cleanup, err := buildServer(cfg)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	f := &loginFixture{
		url: base,
		http: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		redirect: "http://127.0.0.1:9/callback",
	}

	reg, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{f.redirect},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	resp, err := f.http.Post(base+"/apps/dcr", "application/json", strings.NewReader(string(reg)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var app struct {
		ClientID string `json:"client_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&app))
	f.clientID = app.ClientID

	f.postForm(t, "/auth/signup", "/auth/signup", url.Values{"email": {loginTestEmail}, "password": {loginTestPassword}})
	// Signup signs the user in; start each test logged out.
	jar.SetCookies(mustURL(t, base), []*http.Cookie{{Name: "oa_token", Value: "", MaxAge: -1}})
	return f
}

// get fetches path and returns the response with its body read.
func (f *loginFixture) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	resp, err := f.http.Get(f.url + path)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// postForm loads formPage for its CSRF token, then posts form to action
// as a same-origin browser would.
func (f *loginFixture) postForm(t *testing.T, formPage, action string, form url.Values) *http.Response {
	t.Helper()
	_, page := f.get(t, formPage)
	m := loginCSRFField.FindStringSubmatch(page)
	require.NotNil(t, m, "no csrf_token on %s", formPage)
	form.Set("csrf_token", m[1])
	req, _ := http.NewRequest(http.MethodPost, f.url+action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.url)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp
}

func (f *loginFixture) authorizePath() string {
	sum := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.clientID},
		"redirect_uri":          {f.redirect},
		"state":                 {"st-438"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	return "/authorize?" + q.Encode()
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

func TestLoginNext_AuthorizeRoundTripReachesConsent(t *testing.T) {
	f := newLoginFixture(t)
	authorize := f.authorizePath()

	resp, _ := f.get(t, authorize)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	loginURL := resp.Header.Get("Location")
	require.True(t, strings.HasPrefix(loginURL, "/auth/login?next="), loginURL)

	_, page := f.get(t, loginURL)
	m := loginNextField.FindStringSubmatch(page)
	require.NotNil(t, m, "the login form carries next")
	next := html.UnescapeString(m[1])
	assert.Equal(t, authorize, next)

	resp = f.postForm(t, loginURL, "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {next},
	})
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, authorize, resp.Header.Get("Location"), "login returns to /authorize")

	resp, page = f.get(t, resp.Header.Get("Location"))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, page, `value="approve"`, "the consent page for the same request")
	assert.Contains(t, page, f.clientID)
}

func TestLoginNext_NoNextGoesToDashboard(t *testing.T) {
	f := newLoginFixture(t)
	_, page := f.get(t, "/auth/login")
	assert.NotRegexp(t, loginNextField, page)

	resp := f.postForm(t, "/auth/login", "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword},
	})
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/dashboard", resp.Header.Get("Location"))
}

func TestLoginNext_RefusesOffSiteNext(t *testing.T) {
	for _, next := range []string{"https://evil.example/x", "//evil.example/x", `/\evil.example/x`, "javascript:alert(1)"} {
		t.Run(next, func(t *testing.T) {
			f := newLoginFixture(t)
			_, page := f.get(t, "/auth/login?next="+url.QueryEscape(next))
			assert.NotRegexp(t, loginNextField, page, "the form doesn't carry a foreign next")

			resp := f.postForm(t, "/auth/login", "/auth/login", url.Values{
				"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {next},
			})
			require.Equal(t, http.StatusSeeOther, resp.StatusCode)
			assert.Equal(t, "/dashboard", resp.Header.Get("Location"))
		})
	}
}

func TestLoginNext_WrongPasswordKeepsNext(t *testing.T) {
	f := newLoginFixture(t)
	authorize := f.authorizePath()
	loginURL := "/auth/login?next=" + url.QueryEscape(authorize)

	_, page := f.get(t, loginURL)
	m := loginCSRFField.FindStringSubmatch(page)
	require.NotNil(t, m)
	form := url.Values{"csrf_token": {m[1]}, "username": {loginTestEmail}, "password": {"wrong"}, "next": {authorize}}
	req, _ := http.NewRequest(http.MethodPost, f.url+"/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.url)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	m = loginNextField.FindStringSubmatch(string(body))
	require.NotNil(t, m, "the re-rendered form still carries next")
	assert.Equal(t, authorize, html.UnescapeString(m[1]))
}
