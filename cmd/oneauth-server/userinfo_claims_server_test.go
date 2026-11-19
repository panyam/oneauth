package main

// OIDC claims through the reference server: profile claims given at
// signup, the address and phone scopes, the `claims` request parameter,
// and the userinfo token in a form body.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
// See: https://github.com/panyam/oneauth/issues/481

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_UserinfoClaimsFromSignupProfile(t *testing.T) {
	f := newLoginFixtureConfig(t, "  signing_alg: ES256\n  ephemeral_signing_key: true",
		"  oidc: true\nsignup:\n  profile_claims: [name, given_name, address]")

	_, disc := f.get(t, "/.well-known/openid-configuration")
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(disc), &meta))
	assert.Equal(t, true, meta["claims_parameter_supported"])
	assert.Contains(t, meta["scopes_supported"], "address")
	assert.Contains(t, meta["scopes_supported"], "phone")
	assert.Contains(t, meta["claims_supported"], "name")
	assert.Contains(t, meta["claims_supported"], "address")

	// A second user signs up with profile fields, which signs them in.
	f.postForm(t, "/auth/signup", "/auth/signup", url.Values{
		"email": {"grace@example.com"}, "password": {"a-good-password-123"},
		"name": {"Grace Hopper"}, "given_name": {"Grace"}, "address": {"1 Navy Way, Arlington"},
	})
	authorize := f.authorizePath() + "&" + url.Values{
		"scope":  {"openid address"},
		"claims": {`{"userinfo":{"name":{"essential":true}},"id_token":{"given_name":null}}`},
	}.Encode()
	_, consent := f.get(t, authorize)
	form := url.Values{"action": {"approve"}}
	for _, m := range hiddenInput.FindAllStringSubmatch(consent, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	require.NotEmpty(t, form.Get("claims"), "the consent form carries claims")
	req, _ := http.NewRequest(http.MethodPost, f.url+"/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.url)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	tok := redeemCodeAt(t, f, mustURL(t, resp.Header.Get("Location")).Query().Get("code"))

	// The token goes in the form body (RFC 6750 §2.2).
	uresp, err := f.http.PostForm(f.url+"/userinfo", url.Values{"access_token": {tok["access_token"].(string)}})
	require.NoError(t, err)
	defer uresp.Body.Close()
	require.Equal(t, http.StatusOK, uresp.StatusCode)
	var info map[string]any
	require.NoError(t, json.NewDecoder(uresp.Body).Decode(&info))
	assert.Equal(t, "Grace Hopper", info["name"], "asked for by name")
	assert.Equal(t, map[string]any{"formatted": "1 Navy Way, Arlington"}, info["address"], "granted by the address scope")
	assert.Nil(t, info["given_name"], "asked for in the ID token only")
}

func TestServer_SignupProfileClaimsMustBeStandard(t *testing.T) {
	cfg := loadYAML(t, "signup:\n  profile_claims: [name, role]\n")
	assert.ErrorContains(t, checkSignup(cfg), `"role"`)
	assert.NoError(t, checkSignup(loadYAML(t, "signup:\n  profile_claims: [name, address]\n")))
}
