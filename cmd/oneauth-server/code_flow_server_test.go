package main

// The reference server's code flow from end to end: log in from
// /authorize, approve, and redeem the code at /api/token. Before issue
// 438 the server attached its code store to OneAuth after NewOneAuth had
// built the granters, so every redemption answered unsupported_grant_type.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.5
// See: https://github.com/panyam/oneauth/issues/438

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

func TestCodeFlow_ServerRedeemsAnApprovedCode(t *testing.T) {
	f := newLoginFixture(t)
	authorize := f.authorizePath()

	resp := f.postForm(t, "/auth/login?next="+url.QueryEscape(authorize), "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {authorize},
	})
	require.Equal(t, authorize, resp.Header.Get("Location"))

	_, consent := f.get(t, authorize)
	form := url.Values{"action": {"approve"}}
	for _, m := range hiddenInput.FindAllStringSubmatch(consent, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	require.NotEmpty(t, form.Get("csrf_token"), "consent form fields: %v", form)
	req, _ := http.NewRequest(http.MethodPost, f.url+"/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.url)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	cb := mustURL(t, resp.Header.Get("Location"))
	require.Equal(t, "st-438", cb.Query().Get("state"))
	code := cb.Query().Get("code")
	require.NotEmpty(t, code, "approve redirects with a code: %s", cb)

	resp, err = f.http.PostForm(f.url+"/api/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"client_id":     {f.clientID},
		"code_verifier": {strings.Repeat("v", 43)},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	var tok map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	require.Equal(t, http.StatusOK, resp.StatusCode, "token response: %v", tok)
	assert.NotEmpty(t, tok["access_token"])
	assert.Equal(t, "Bearer", tok["token_type"])
}

// The session /authorize reads the subject from must name the user by
// the same ID the password grant puts in `sub`. Before issue 339
// localauth handed the session no user_id, so the server fell back to the
// login name and the same person had two subjects, one per grant.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken (sub)
func TestCodeFlow_SubjectMatchesThePasswordGrant(t *testing.T) {
	f := newLoginFixture(t)
	code := approveCode(t, f, f.authorizePath())
	codeTok := redeemCodeAt(t, f, code)

	resp, err := f.http.PostForm(f.url+"/api/token", url.Values{
		"grant_type": {"password"}, "username": {loginTestEmail}, "password": {loginTestPassword},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	var pw map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pw))
	require.Equal(t, http.StatusOK, resp.StatusCode, "password grant: %v", pw)

	codeSub := subjectOf(t, f, codeTok["access_token"].(string))
	assert.Equal(t, subjectOf(t, f, pw["access_token"].(string)), codeSub)
	assert.NotEqual(t, loginTestEmail, codeSub, "sub is the user ID, not the login name")
}

// approveCode logs in from authorize, approves, and returns the code.
func approveCode(t *testing.T, f *loginFixture, authorize string) string {
	t.Helper()
	resp := f.postForm(t, "/auth/login?next="+url.QueryEscape(authorize), "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {authorize},
	})
	require.Equal(t, authorize, resp.Header.Get("Location"))

	_, consent := f.get(t, authorize)
	form := url.Values{"action": {"approve"}}
	for _, m := range hiddenInput.FindAllStringSubmatch(consent, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	req, _ := http.NewRequest(http.MethodPost, f.url+"/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.url)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	code := mustURL(t, resp.Header.Get("Location")).Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

// redeemCodeAt redeems code for the fixture's public client.
func redeemCodeAt(t *testing.T, f *loginFixture, code string) map[string]any {
	t.Helper()
	resp, err := f.http.PostForm(f.url+"/api/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"client_id":     {f.clientID},
		"code_verifier": {strings.Repeat("v", 43)},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	var tok map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	require.Equal(t, http.StatusOK, resp.StatusCode, "token response: %v", tok)
	return tok
}

// subjectOf asks /api/me who the access token belongs to.
func subjectOf(t *testing.T, f *loginFixture, token string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.url+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var me map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&me))
	return me["user_id"].(string)
}
