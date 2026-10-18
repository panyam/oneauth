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
