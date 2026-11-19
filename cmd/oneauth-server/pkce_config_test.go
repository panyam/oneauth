package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKCEConfig_KnownValuesOnly(t *testing.T) {
	for _, v := range []string{"", "required", "optional_for_confidential"} {
		assert.NoError(t, checkPKCE(loadYAML(t, fapiBase+"code_flow:\n  enabled: true\n  pkce: \""+v+"\"\n")), v)
	}
	assert.Error(t, checkPKCE(loadYAML(t, fapiBase+"code_flow:\n  enabled: true\n  pkce: sometimes\n")))
}

// FAPI 2.0 requires PKCE from every client, so the server refuses to start
// with fapi2 and optional PKCE.
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2
func TestPKCEConfig_FAPI2NeedsRequired(t *testing.T) {
	cfg := loadYAML(t, fapiSigning+"fapi2: true\ndpop:\n  enabled: true\ncode_flow:\n  enabled: true\n  pkce: optional_for_confidential\n  par:\n    enabled: true\n")
	err := checkFAPI2(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code_flow.pkce")
}

// registerConfidential registers a client_secret_basic client for the
// fixture's redirect URI and returns its id and secret.
func registerConfidential(t *testing.T, f *loginFixture) (string, string) {
	t.Helper()
	reg, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{f.redirect},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	resp, err := f.http.Post(f.url+"/apps/dcr", "application/json", strings.NewReader(string(reg)))
	require.NoError(t, err)
	defer resp.Body.Close()
	var app map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&app))
	require.Equal(t, http.StatusCreated, resp.StatusCode, "DCR: %v", app)
	return app["client_id"].(string), app["client_secret"].(string)
}

func noPKCEAuthorize(f *loginFixture, clientID string) string {
	return "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {f.redirect}, "state": {"st-290"},
	}.Encode()
}

// With code_flow.pkce: optional_for_confidential, a confidential client
// runs the code flow without PKCE, as an OIDC Core relying party does, and
// authenticates at the token endpoint instead.
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
func TestServer_PKCEOptionalForConfidential_CodeFlowWithoutPKCE(t *testing.T) {
	f := newLoginFixtureConfig(t, "", "  pkce: optional_for_confidential")
	clientID, secret := registerConfidential(t, f)
	code := approveCode(t, f, noPKCEAuthorize(f, clientID))

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.redirect}}
	req, _ := http.NewRequest(http.MethodPost, f.url+"/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var tok map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	require.Equal(t, http.StatusOK, resp.StatusCode, "token: %v", tok)
	assert.NotEmpty(t, tok["access_token"])
}

// By default the same request is refused at /authorize, back to the
// client with invalid_request.
func TestServer_PKCERequiredByDefault(t *testing.T) {
	f := newLoginFixture(t)
	clientID, _ := registerConfidential(t, f)
	f.postForm(t, "/auth/login", "/auth/login", url.Values{"username": {loginTestEmail}, "password": {loginTestPassword}})
	resp, _ := f.get(t, noPKCEAuthorize(f, clientID))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := mustURL(t, resp.Header.Get("Location"))
	assert.Equal(t, "invalid_request", loc.Query().Get("error"))
	assert.Contains(t, loc.Query().Get("error_description"), "code_challenge is required")
}
