package oauch

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/panyam/oneauth/testutil"
	"github.com/stretchr/testify/require"
)

// TestOAuch runs OAuch's test set against oneauth-server and checks the
// results against expected.yaml (issue 567). `make testoauch` starts both
// servers and sets OAUCH_URL and OAUCH_AS_URL; without them the test skips.
// A run takes about 15 minutes, most of it waiting for OAuch's timed tests.
func TestOAuch(t *testing.T) {
	oauchURL, asURL := os.Getenv("OAUCH_URL"), os.Getenv("OAUCH_AS_URL")
	if oauchURL == "" || asURL == "" {
		t.Skip("OAUCH_URL and OAUCH_AS_URL not set; run `make testoauch`")
	}
	expected, err := LoadExpected("expected.yaml")
	require.NoError(t, err)

	// oneauth-server uses the OIDF harness's test certificate.
	hc := insecureClient(t)
	var disc Discovery
	getJSON(t, hc, asURL+"/.well-known/openid-configuration", &disc)

	user, pass := "oauch@example.com", "oauch-pass-123"
	require.NoError(t, testutil.SignUp(hc, asURL, user, pass))
	callback := oauchURL + "/Callback"
	def, alt := register(t, hc, disc.RegistrationEndpoint, callback, "oauch-default"), register(t, hc, disc.RegistrationEndpoint, callback, "oauch-alternative")

	as, err := url.Parse(asURL)
	require.NoError(t, err)
	run := &Run{OAuchURL: oauchURL, ASHost: as.Host, Username: user, Password: pass, Logf: t.Logf}
	require.NoError(t, run.Start())
	defer run.Close()

	name := fmt.Sprintf("oneauth-%d", time.Now().Unix())
	siteID, err := run.Import(NewSite(name, disc, callback, def, alt))
	require.NoError(t, err)
	t.Logf("OAuch site %s (%s)", name, siteID)

	require.NoError(t, run.RunTests(siteID, 10*time.Minute))
	results := export(t, run, siteID)
	if ids, when := Pending(results); len(ids) > 0 {
		t.Logf("%d timed tests pending: %v", len(ids), ids)
		require.NoError(t, run.Resume(siteID, when.Add(15*time.Second), 5*time.Minute))
		results = export(t, run, siteID)
	}

	rep := Compare(results, expected)
	for _, id := range rep.NowPassing {
		t.Logf("now passes, remove from expected.yaml: %s", id)
	}
	for _, id := range rep.Missing {
		t.Errorf("in expected.yaml but not in this run: %s", id)
	}
	for _, u := range rep.Unexpected {
		t.Errorf("unexpected: %s", u)
	}
	// The conformance runner reads this line for the report.
	fmt.Println(rep.Summary())
}

// export fetches the site's results and keeps a copy for triage in
// OAUCH_REPORT_DIR when it's set.
func export(t *testing.T, run *Run, siteID string) []Result {
	t.Helper()
	raw, err := run.Export(siteID)
	require.NoError(t, err)
	if dir := os.Getenv("OAUCH_REPORT_DIR"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "oauch-export.json"), raw, 0o644))
	}
	results, _, err := ParseExport(raw)
	require.NoError(t, err)
	return results
}

func insecureClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{
		Jar:       jar,
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // test certificate
	}
}

func getJSON(t *testing.T, hc *http.Client, u string, out any) {
	t.Helper()
	resp, err := hc.Get(u)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, u)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
}

// register makes a confidential client through open DCR. testutil's
// RegisterClient returns only the ID, and OAuch needs the secret too.
func register(t *testing.T, hc *http.Client, endpoint, callback, name string) Client {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"client_name":                name,
		"redirect_uris":              []string{callback},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      Scope,
	})
	resp, err := hc.Post(endpoint, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, resp.StatusCode, "DCR for %s", name)
	var c struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&c))
	return Client{ClientId: c.ClientID, ClientSecret: c.ClientSecret, Scope: Scope}
}
