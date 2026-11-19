package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushAuthorization posts the fixture's authorization request to /par and
// returns the request_uri.
func pushAuthorization(t *testing.T, f *loginFixture) string {
	t.Helper()
	sum := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	resp, err := f.http.PostForm(f.url+"/par", url.Values{
		"response_type":         {"code"},
		"client_id":             {f.clientID},
		"redirect_uri":          {f.redirect},
		"state":                 {"st-382"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.Equal(t, http.StatusCreated, resp.StatusCode, "PAR response: %v", out)
	uri, _ := out["request_uri"].(string)
	require.NotEmpty(t, uri)
	return uri
}

// runPushedCodeFlow pushes a request, approves it, redeems the code, and
// checks a second redemption is refused. It returns the code and the
// request_uri.
func runPushedCodeFlow(t *testing.T, f *loginFixture) (string, string) {
	t.Helper()
	uri := pushAuthorization(t, f)
	authorize := "/authorize?" + url.Values{"client_id": {f.clientID}, "request_uri": {uri}}.Encode()
	code := approveCode(t, f, authorize)
	tok := redeemCodeAt(t, f, code)
	require.NotEmpty(t, tok["access_token"])

	resp, err := f.http.PostForm(f.url+"/api/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.redirect},
		"client_id": {f.clientID}, "code_verifier": {strings.Repeat("v", 43)},
	})
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a reused code must be refused")
	return code, uri
}

// code_flow.store type fs serves the whole pushed code flow, and the
// directory holds neither the code nor the request_uri.
// See: https://www.rfc-editor.org/rfc/rfc9126
// See: https://cwe.mitre.org/data/definitions/312.html
func TestServer_FSCodeStoreServesPushedCodeFlow(t *testing.T) {
	dir := t.TempDir()
	f := newLoginFixtureConfig(t, "", fmt.Sprintf("  store:\n    type: fs\n    fs:\n      path: %s\n  par:\n    enabled: true", dir))
	code, uri := runPushedCodeFlow(t, f)

	for _, sub := range []string{"authorization_codes", "pushed_authorization_requests"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		require.NoError(t, err, sub)
		require.Len(t, entries, 1, sub)
		b, err := os.ReadFile(filepath.Join(dir, sub, entries[0].Name()))
		require.NoError(t, err)
		ref := strings.TrimPrefix(uri, "urn:ietf:params:oauth:request_uri:")
		for _, secret := range []string{code, ref} {
			assert.NotContains(t, entries[0].Name()+string(b), secret, "%s holds a plaintext value", sub)
		}
	}
}

// code_flow.store type gae serves the same flow. Skips without the
// Datastore emulator (make testds).
func TestServer_GAECodeStoreServesPushedCodeFlow(t *testing.T) {
	project := os.Getenv("DATASTORE_PROJECT_ID")
	if project == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE code store test")
	}
	f := newLoginFixtureConfig(t, "", fmt.Sprintf("  store:\n    type: gae\n    gae:\n      project: %s\n      namespace: oneauth-server-382-test\n  par:\n    enabled: true", project))
	runPushedCodeFlow(t, f)
}
