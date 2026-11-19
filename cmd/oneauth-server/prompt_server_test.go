package main

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OIDC Core §3.1.2.1 prompt and max_age through the reference server: the
// real login page, the session cookie's iat as auth_time, and
// code_flow.consent.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// See: https://github.com/panyam/oneauth/issues/453

func (f *loginFixture) login(t *testing.T, next string) *http.Response {
	t.Helper()
	return f.postForm(t, "/auth/login?next="+url.QueryEscape(next), "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {next},
	})
}

func withQuery(t *testing.T, path string, kv ...string) string {
	t.Helper()
	u := mustURL(t, path)
	q := u.Query()
	for i := 0; i < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// With code_flow.consent.remember, one approval lets a later prompt=none
// request get a code without any page.
func TestServer_RememberedConsentAnswersPromptNone(t *testing.T) {
	f := newLoginFixtureConfig(t, "", "  consent:\n    remember: true\n    lifetime: 1h")
	approveCode(t, f, f.authorizePath())

	resp, _ := f.get(t, withQuery(t, f.authorizePath(), "prompt", "none"))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	cb := mustURL(t, resp.Header.Get("Location"))
	assert.NotEmpty(t, cb.Query().Get("code"), "callback %s", cb)
	assert.Empty(t, cb.Query().Get("error"))
}

// Without it, prompt=none from a logged-in user is consent_required, and
// from a browser with no session login_required.
func TestServer_PromptNoneWithoutRememberedConsent(t *testing.T) {
	f := newLoginFixture(t)
	resp, _ := f.get(t, withQuery(t, f.authorizePath(), "prompt", "none"))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "login_required", mustURL(t, resp.Header.Get("Location")).Query().Get("error"))

	approveCode(t, f, f.authorizePath())
	resp, _ = f.get(t, withQuery(t, f.authorizePath(), "prompt", "none"))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "consent_required", mustURL(t, resp.Header.Get("Location")).Query().Get("error"))
}

// prompt=login sends a logged-in user to the login page. Logging in again
// mints a new session, and the return URL then shows the consent page.
func TestServer_PromptLoginGoesThroughLoginOnce(t *testing.T) {
	f := newLoginFixture(t)
	approveCode(t, f, f.authorizePath())

	resp, _ := f.get(t, withQuery(t, f.authorizePath(), "prompt", "login"))
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	loc := mustURL(t, resp.Header.Get("Location"))
	require.Equal(t, "/auth/login", loc.Path)
	next := loc.Query().Get("next")
	require.Contains(t, next, "oa_login_after=")

	resp = f.login(t, next)
	require.Equal(t, next, resp.Header.Get("Location"))
	page, body := f.get(t, next)
	assert.Equal(t, http.StatusOK, page.StatusCode, "location %s", page.Header.Get("Location"))
	assert.Contains(t, body, `value="approve"`)
}
