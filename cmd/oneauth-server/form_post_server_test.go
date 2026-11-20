package main

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// response_mode=form_post through the reference server (issue 500). The
// server-wide CSP allows script only from 'self', so the form page
// replaces it with a policy that runs one script by nonce, never
// 'unsafe-inline'. Discovery lists the modes /authorize accepts.
//
// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
// See: https://www.w3.org/TR/CSP3/#security-nonces
// See: https://github.com/panyam/oneauth/issues/500

var (
	serverFormInput = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
	serverFormNonce = regexp.MustCompile(`<script nonce="([^"]+)">`)
)

// serverFormPost checks resp is a form_post page and returns the values it
// posts to the fixture's redirect_uri.
func serverFormPost(t *testing.T, f *loginFixture, resp *http.Response) url.Values {
	t.Helper()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	require.Equal(t, http.StatusOK, resp.StatusCode, "Location %q body %q", resp.Header.Get("Location"), body)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))

	csp := resp.Header.Values("Content-Security-Policy")
	require.Len(t, csp, 1, "one policy, replacing the server's")
	assert.NotContains(t, csp[0], "unsafe-inline")
	assert.Contains(t, csp[0], "frame-ancestors 'none'")
	assert.NotContains(t, csp[0], "form-action", "issue 497")
	nonce := serverFormNonce.FindStringSubmatch(body)
	require.NotNil(t, nonce, body)
	assert.Contains(t, csp[0], "script-src 'nonce-"+nonce[1]+"'")
	assert.Contains(t, body, `action="`+f.redirect+`"`)
	assert.Contains(t, body, "<noscript>")

	values := url.Values{}
	for _, m := range serverFormInput.FindAllStringSubmatch(body, -1) {
		values.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return values
}

// A logged-in user approves on the consent page, and the code comes back
// as a form post that redeems at the token endpoint.
func TestServer_FormPostApproveRedeems(t *testing.T) {
	f := newLoginFixture(t)
	authorize := withQuery(t, f.authorizePath(), "response_mode", "form_post")
	resp := f.login(t, authorize)
	require.Equal(t, authorize, resp.Header.Get("Location"))

	_, consent := f.get(t, authorize)
	form := url.Values{"action": {"approve"}}
	for _, m := range hiddenInput.FindAllStringSubmatch(consent, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	assert.Equal(t, "form_post", form.Get("response_mode"), "the consent form carries response_mode")
	req, _ := http.NewRequest(http.MethodPost, f.url+"/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.url)
	resp, err := f.http.Do(req)
	require.NoError(t, err)

	values := serverFormPost(t, f, resp)
	assert.Equal(t, "st-438", values.Get("state"))
	assert.Equal(t, f.url, values.Get("iss"))
	tokens := redeemCodeAt(t, f, values.Get("code"))
	assert.NotEmpty(t, tokens["access_token"], tokens)
}

// prompt=none with no session is login_required, posted to the client.
func TestServer_FormPostError(t *testing.T) {
	f := newLoginFixture(t)
	resp, err := f.http.Get(f.url + withQuery(t, f.authorizePath(), "response_mode", "form_post", "prompt", "none"))
	require.NoError(t, err)
	values := serverFormPost(t, f, resp)
	assert.Equal(t, "login_required", values.Get("error"))
	assert.Equal(t, "st-438", values.Get("state"))
}

// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func TestServer_DiscoveryListsResponseModes(t *testing.T) {
	f := newLoginFixture(t)
	resp, body := f.get(t, "/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var meta struct {
		ResponseModes []string `json:"response_modes_supported"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &meta))
	assert.Equal(t, []string{"query", "form_post"}, meta.ResponseModes, "no fragment without the implicit types")

	cfg := &Config{}
	cfg.CodeFlow.Enabled, cfg.CodeFlow.OIDC, cfg.CodeFlow.Implicit = true, true, true
	cfg.JWT.SigningAlg = "ES256"
	on := serverASMetadata(cfg, "https://as.example", true)
	assert.Equal(t, []string{"query", "fragment", "form_post"}, on.ResponseModesSupported)
	assert.Empty(t, serverASMetadata(cfg, "https://as.example", false).ResponseModesSupported, "no /authorize, no response modes")
}
