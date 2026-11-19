package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// newDeviceFlowFixture builds the reference server with the device flow on
// the given store block, and registers a public client allowed the device
// grant.
func newDeviceFlowFixture(t *testing.T, storeYAML string) (*loginFixture, string) {
	t.Helper()
	f := newLoginFixtureConfig(t, "", "device_flow:\n  enabled: true\n"+storeYAML)
	reg, _ := json.Marshal(map[string]any{
		"client_name":                "device-test",
		"grant_types":                []string{deviceGrantType},
		"token_endpoint_auth_method": "none",
	})
	resp, err := f.http.Post(f.url+"/apps/dcr", "application/json", strings.NewReader(string(reg)))
	require.NoError(t, err)
	defer resp.Body.Close()
	var app map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&app))
	require.Equal(t, http.StatusCreated, resp.StatusCode, "DCR: %v", app)
	return f, app["client_id"].(string)
}

// runDeviceFlow drives RFC 8628 through the reference server: authorize,
// sign in, enter the user code, approve, poll for tokens, then check a
// second poll with the same device code is refused. afterApprove, if not
// nil, runs between the approval and the first poll, while the record
// still exists (a successful poll deletes it).
func runDeviceFlow(t *testing.T, f *loginFixture, clientID string, afterApprove func(deviceCode string)) {
	t.Helper()
	resp, err := f.http.PostForm(f.url+"/device/authorize", url.Values{"client_id": {clientID}})
	require.NoError(t, err)
	var da map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&da))
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "device authorize: %v", da)
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)

	f.postForm(t, "/auth/login", "/auth/login", url.Values{"username": {loginTestEmail}, "password": {loginTestPassword}})
	resp = f.postForm(t, "/device", "/device", url.Values{"user_code": {userCode}})
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, "submit user code")
	consentPath := resp.Header.Get("Location")
	require.NotEmpty(t, consentPath)

	_, consent := f.get(t, consentPath)
	form := url.Values{"action": {"approve"}}
	for _, m := range hiddenInput.FindAllStringSubmatch(consent, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	req, _ := http.NewRequest(http.MethodPost, f.url+"/device/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.url)
	resp, err = f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Less(t, resp.StatusCode, 400, "approve")
	if afterApprove != nil {
		afterApprove(deviceCode)
	}

	poll := func() (int, map[string]any) {
		resp, err := f.http.PostForm(f.url+"/api/token", url.Values{"grant_type": {deviceGrantType}, "device_code": {deviceCode}, "client_id": {clientID}})
		require.NoError(t, err)
		defer resp.Body.Close()
		var out map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		return resp.StatusCode, out
	}
	status, tok := poll()
	require.Equal(t, http.StatusOK, status, "token: %v", tok)
	require.NotEmpty(t, tok["access_token"])
	status, again := poll()
	assert.Equal(t, http.StatusBadRequest, status, "a redeemed device code must be refused: %v", again)
}

// device_flow.store type fs serves the whole device flow, and while the
// approved record waits to be polled, the directory doesn't hold the
// device code (issue 473).
// See: https://www.rfc-editor.org/rfc/rfc8628
// See: https://cwe.mitre.org/data/definitions/312.html
func TestServer_FSDeviceStoreServesDeviceFlow(t *testing.T) {
	dir := t.TempDir()
	f, clientID := newDeviceFlowFixture(t, fmt.Sprintf("  store:\n    type: fs\n    fs:\n      path: %s\n", dir))
	runDeviceFlow(t, f, clientID, func(deviceCode string) {
		files := 0
		err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			files++
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			assert.NotContains(t, info.Name()+string(b), deviceCode, "%s holds the device code", p)
			return nil
		})
		require.NoError(t, err)
		require.NotZero(t, files, "the approved authorization is on disk")
	})
}

// device_flow.store type gorm. The reference server only drives
// Postgres, so this skips without the database make testpg starts.
func TestServer_GORMDeviceStoreServesDeviceFlow(t *testing.T) {
	db := os.Getenv("ONEAUTH_TEST_PGDB")
	if db == "" {
		t.Skip("ONEAUTH_TEST_PGDB not set, skipping GORM device store test")
	}
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		env("ONEAUTH_TEST_PGHOST", "localhost"), env("ONEAUTH_TEST_PGPORT", "5432"),
		env("ONEAUTH_TEST_PGUSER", "postgres"), env("ONEAUTH_TEST_PGPASSWORD", "testpassword"), db)
	f, clientID := newDeviceFlowFixture(t, fmt.Sprintf("  store:\n    type: gorm\n    gorm:\n      driver: postgres\n      dsn: \"%s\"\n", dsn))
	runDeviceFlow(t, f, clientID, nil)
}

// device_flow.store type gae. Skips without the Datastore emulator (make
// testds runs it).
func TestServer_GAEDeviceStoreServesDeviceFlow(t *testing.T) {
	project := os.Getenv("DATASTORE_PROJECT_ID")
	if project == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE device store test")
	}
	f, clientID := newDeviceFlowFixture(t, fmt.Sprintf("  store:\n    type: gae\n    gae:\n      project: %s\n      namespace: oneauth-server-473-test\n", project))
	runDeviceFlow(t, f, clientID, nil)
}
