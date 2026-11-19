package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A relying party on another site posts the authorization request as a
// form (OIDC Core §3.1.2.1). The server's CSRF middleware would refuse
// that POST as a consent decision, so it must be sent on to GET
// /authorize, which then shows the logged-in user the consent page.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// See: https://github.com/panyam/oneauth/issues/478
func TestServer_CrossSitePostedAuthorizationRequestReachesConsent(t *testing.T) {
	f := newLoginFixture(t)
	authorize := f.authorizePath()
	resp := f.postForm(t, "/auth/login?next="+url.QueryEscape(authorize), "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {authorize},
	})
	require.Equal(t, authorize, resp.Header.Get("Location"))

	params := mustURL(t, authorize).Query()
	req, _ := http.NewRequest(http.MethodPost, f.url+"/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://rp.example")
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	loc := mustURL(t, resp.Header.Get("Location"))
	assert.Equal(t, "/authorize", loc.Path)
	assert.Equal(t, params, loc.Query())

	page, consent := f.get(t, loc.String())
	assert.Equal(t, http.StatusOK, page.StatusCode)
	assert.Contains(t, consent, `value="approve"`)
}

// The same cross-site POST carrying a consent decision is refused by the
// CSRF middleware: only a POST without `action` is redirected.
func TestServer_CrossSiteConsentDecisionIsStillRefused(t *testing.T) {
	f := newLoginFixture(t)
	authorize := f.authorizePath()
	f.postForm(t, "/auth/login?next="+url.QueryEscape(authorize), "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {authorize},
	})

	form := mustURL(t, authorize).Query()
	form.Set("action", "approve")
	req, _ := http.NewRequest(http.MethodPost, f.url+"/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://rp.example")
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
}
