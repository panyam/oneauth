package cmd

// End-to-end tests for `oneauth token <subcommand>` against a synthetic
// in-memory AS. We exercise the four grant subcommands and the flag
// guards (required flags, mutually-exclusive *-stdin variants).
//
// The browser flow's loopback + PKCE machinery is owned by
// client/browser_login.go and has its own tests; here we cover only
// the CLI-side wiring (--no-browser prints the URL, sub-command wires
// the right SDK call). Wire-shape coverage against a real RFC-compliant
// AS lives in tests/keycloak/oneauth_cli_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redirectStdin replaces os.Stdin with a pipe pre-filled with the given
// payload, returns a restore function. Used by *-stdin flag tests so
// readStdinSecret reads from a controlled source rather than the
// terminal.
func redirectStdin(t *testing.T, payload string) (orig *os.File, restore func(*os.File)) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(payload)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	orig = os.Stdin
	os.Stdin = r
	return orig, func(orig *os.File) { os.Stdin = orig; _ = r.Close() }
}

// syntheticAS spins up a minimal AS that serves RFC 8414 metadata at
// /.well-known/oauth-authorization-server and a /token endpoint that
// captures the parsed form (so a test can assert on grant_type and
// per-grant inputs) and emits a deterministic token response.
type syntheticAS struct {
	srv         *httptest.Server
	tokenForm   chan map[string][]string
	tokenCount  atomic.Int32
	includeRT   bool   // include refresh_token in /token responses
	tokenStatus int    // override status (default 200)
	tokenError  string // override OAuth error response
}

func newSyntheticAS(t *testing.T) *syntheticAS {
	t.Helper()
	as := &syntheticAS{
		tokenForm: make(chan map[string][]string, 4),
		includeRT: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                as.srv.URL,
			"authorization_endpoint":                as.srv.URL + "/authorize",
			"token_endpoint":                        as.srv.URL + "/token",
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		select {
		case as.tokenForm <- r.Form:
		default:
		}
		if as.tokenError != "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             as.tokenError,
				"error_description": "synthetic " + as.tokenError,
			})
			return
		}
		if as.tokenStatus != 0 {
			w.WriteHeader(as.tokenStatus)
		}
		n := as.tokenCount.Add(1)
		resp := map[string]any{
			"access_token": fmt.Sprintf("AT-%d", n),
			"token_type":   "Bearer",
			"expires_in":   1800,
			"scope":        r.FormValue("scope"),
		}
		if as.includeRT {
			resp["refresh_token"] = fmt.Sprintf("RT-%d", n)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	// Legacy oneauth-native JSON endpoint — AuthClient.Login (the
	// password grant path) targets this path rather than the standards
	// /token endpoint. See client/SUMMARY.md "Legacy note".
	mux.HandleFunc("/auth/cli/token", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		// Capture as a form-like map so existing tokenForm assertions
		// uniformly see {grant_type: [...], ...}.
		form := map[string][]string{}
		for k, v := range req {
			form[k] = []string{v}
		}
		select {
		case as.tokenForm <- form:
		default:
		}
		n := as.tokenCount.Add(1)
		resp := map[string]any{
			"access_token": fmt.Sprintf("AT-%d", n),
			"token_type":   "Bearer",
			"expires_in":   1800,
		}
		if as.includeRT {
			resp["refresh_token"] = fmt.Sprintf("RT-%d", n)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

// TestRunClientCredentials_HappyPath — the subcommand discovers the
// AS, sends a client_credentials grant with the negotiated auth method,
// and prints the resulting token in the requested format.
func TestRunClientCredentials_HappyPath(t *testing.T) {
	as := newSyntheticAS(t)
	tf := &tokenFlags{format: "json"}
	cc := &clientCredsFlags{
		clientID:     "demo",
		clientSecret: "shh",
		scopes:       "read write",
	}
	var stdout bytes.Buffer
	require.NoError(t, runClientCredentials(context.Background(), &stdout, as.srv.URL, tf, cc))

	form := <-as.tokenForm
	assert.Equal(t, []string{"client_credentials"}, form["grant_type"])
	assert.Equal(t, []string{"read write"}, form["scope"])

	var out tokenOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, "AT-1", out.AccessToken)
	assert.Equal(t, "RT-1", out.RefreshToken)
	assert.Equal(t, "Bearer", out.TokenType)
	assert.Equal(t, as.srv.URL, out.Issuer)
}

// TestRunClientCredentials_ResourceForwarded — RFC 8707 resource
// indicator flows from the --resource flag onto the token request.
func TestRunClientCredentials_ResourceForwarded(t *testing.T) {
	as := newSyntheticAS(t)
	tf := &tokenFlags{format: "json"}
	cc := &clientCredsFlags{
		clientID:     "demo",
		clientSecret: "shh",
		resource:     "https://api.example.com",
	}
	var stdout bytes.Buffer
	require.NoError(t, runClientCredentials(context.Background(), &stdout, as.srv.URL, tf, cc))
	form := <-as.tokenForm
	assert.Equal(t, []string{"https://api.example.com"}, form["resource"],
		"--resource MUST be sent as a `resource` form value (RFC 8707 §2)")
}

// TestRunClientCredentials_StdinSecret — the CLI reads the secret from
// stdin via readStdinSecret when --client-secret-stdin is set, avoiding
// the secret hitting argv.
func TestRunClientCredentials_StdinSecret(t *testing.T) {
	as := newSyntheticAS(t)
	tf := &tokenFlags{format: "json"}
	cc := &clientCredsFlags{
		clientID:          "demo",
		clientSecretStdin: true,
	}
	stdin, restore := redirectStdin(t, "stdin-secret\n")
	defer restore(stdin)

	var stdout bytes.Buffer
	require.NoError(t, runClientCredentials(context.Background(), &stdout, as.srv.URL, tf, cc))

	form := <-as.tokenForm
	// Either client_secret_basic (header) or client_secret_post (form)
	// is RFC-compliant. Synthetic AS advertises both; SDK picks one. We
	// only assert the wire shape carried the secret somehow — auth
	// method selection is covered by client/auth_method_test.go.
	if got := form["client_secret"]; len(got) > 0 {
		assert.Equal(t, "stdin-secret", got[0])
	}
	require.NotEmpty(t, stdout.Bytes(), "happy-path produces output")
}

// TestRunClientCredentials_MutexFlags — --client-secret and
// --client-secret-stdin together fail before any HTTP call.
func TestRunClientCredentials_MutexFlags(t *testing.T) {
	tf := &tokenFlags{format: "json"}
	cc := &clientCredsFlags{
		clientID:          "demo",
		clientSecret:      "literal",
		clientSecretStdin: true,
	}
	err := runClientCredentials(context.Background(), &bytes.Buffer{}, "http://unused", tf, cc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// TestRunPassword_HappyPath_DeprecationToStderr — the password grant
// (ROPC) prints a deprecation warning to stderr, posts JSON to the
// legacy /auth/cli/token endpoint, and emits the token to stdout.
func TestRunPassword_HappyPath_DeprecationToStderr(t *testing.T) {
	as := newSyntheticAS(t)
	tf := &tokenFlags{format: "json"}
	pf := &passwordFlags{
		clientID: "cli",
		user:     "user@example.com",
		password: "hunter2",
		scopes:   "openid",
	}
	var stdout, stderr bytes.Buffer
	require.NoError(t, runPassword(context.Background(), &stdout, &stderr, as.srv.URL, tf, pf))

	assert.Contains(t, stderr.String(), "warning")
	assert.Contains(t, stderr.String(), "deprecated")

	form := <-as.tokenForm
	assert.Equal(t, []string{"password"}, form["grant_type"])
	assert.Equal(t, []string{"user@example.com"}, form["username"])
	assert.Equal(t, []string{"hunter2"}, form["password"])
	assert.Equal(t, []string{"openid"}, form["scope"])

	var out tokenOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, "AT-1", out.AccessToken)
}

// TestRunRefresh_HappyPath — the subcommand sends grant_type=refresh_token
// with the supplied refresh_token + scopes.
func TestRunRefresh_HappyPath(t *testing.T) {
	as := newSyntheticAS(t)
	tf := &tokenFlags{format: "json"}
	rf := &refreshFlags{
		clientID:     "demo",
		refreshToken: "the-refresh",
		scopes:       "read",
	}
	var stdout bytes.Buffer
	require.NoError(t, runRefresh(context.Background(), &stdout, as.srv.URL, tf, rf))

	form := <-as.tokenForm
	assert.Equal(t, []string{"refresh_token"}, form["grant_type"])
	assert.Equal(t, []string{"the-refresh"}, form["refresh_token"])
	assert.Equal(t, []string{"read"}, form["scope"])

	var out tokenOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, "AT-1", out.AccessToken)
}

// TestRunRefresh_RotatedRefreshTokenInOutput — when the AS rotates the
// refresh token (RFC 6749 §6 optional), the new token appears in the
// CLI output.
func TestRunRefresh_RotatedRefreshTokenInOutput(t *testing.T) {
	as := newSyntheticAS(t)
	tf := &tokenFlags{format: "json"}
	rf := &refreshFlags{
		clientID:     "demo",
		refreshToken: "old-refresh",
	}
	var stdout bytes.Buffer
	require.NoError(t, runRefresh(context.Background(), &stdout, as.srv.URL, tf, rf))

	var out tokenOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, "RT-1", out.RefreshToken, "rotated refresh token surfaces in stdout")
}

// TestRunRefresh_MissingRefreshToken — neither --refresh-token nor
// --refresh-token-stdin → error before any HTTP call.
func TestRunRefresh_MissingRefreshToken(t *testing.T) {
	tf := &tokenFlags{format: "json"}
	rf := &refreshFlags{clientID: "demo"}
	err := runRefresh(context.Background(), &bytes.Buffer{}, "http://unused", tf, rf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--refresh-token")
}

// TestRunBrowser_NoBrowserPrintsURL — with --no-browser, the auth URL
// is printed to stderr in the documented "Open this URL …" envelope.
// We don't follow the URL here — the SDK's browser_login_test owns the
// end-to-end loopback flow; we just verify the CLI honors the flag.
func TestRunBrowser_NoBrowserPrintsURL(t *testing.T) {
	as := newSyntheticAS(t)
	tf := &tokenFlags{format: "json"}
	bf := &browserFlags{
		clientID:  "cli",
		noBrowser: true,
		timeout:   200 * time.Millisecond, // bound the wait — we expect a timeout
	}
	var stdout, stderr bytes.Buffer
	err := runBrowser(context.Background(), &stdout, &stderr, as.srv.URL, tf, bf)
	require.Error(t, err, "expected timeout since we never hit the loopback")
	assert.Contains(t, stderr.String(), "Open this URL in a browser:")
	assert.Contains(t, stderr.String(), as.srv.URL+"/authorize")
	assert.Contains(t, stderr.String(), "code_challenge_method=S256",
		"PKCE S256 challenge MUST appear in the auth URL the CLI prints")
}

// TestCobraTree_RequiredFlags — Cobra's MarkFlagRequired surfaces a
// usage error before RunE fires when --client-id is omitted.
func TestCobraTree_RequiredFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"browser", []string{"token", "browser", "http://unused"}},
		{"client-credentials", []string{"token", "client-credentials", "http://unused"}},
		{"password", []string{"token", "password", "http://unused"}},
		{"refresh", []string{"token", "refresh", "http://unused"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := NewRoot()
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			root.SetArgs(c.args)
			err := root.Execute()
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), "client-id",
				"missing --client-id MUST surface in the error")
		})
	}
}
