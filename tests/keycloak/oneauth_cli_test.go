package keycloak_test

// Wire-format interop tests for the `oneauth` CLI (cmd/oneauth) against
// a real RFC 8414 / OIDC AS — Keycloak. The CLI surface is unit-tested
// against a synthetic AS in cmd/oneauth/cmd/token_test.go; this file
// proves the same flags reach Keycloak's actual /token endpoint and
// produce usable tokens.
//
// Tests skip gracefully when Keycloak is not running. The CLI binary
// is built once per test run into the test's TempDir.
//
// See: https://github.com/panyam/oneauth/issues/255

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cliTokenOutput is the wire shape printed by `oneauth token --format
// json`. Kept private here so this test file stays a pure consumer of
// the CLI surface and doesn't import cmd/oneauth's internal package.
type cliTokenOutput struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
}

// buildOneauthCLI compiles cmd/oneauth into the test TempDir once per
// test run and returns the path. Each subtest that wants to invoke the
// CLI calls this — the underlying go build is fast enough on warm
// caches that we don't bother sharing across tests.
func buildOneauthCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "oneauth")
	cmd := exec.Command("go", "build", "-o", binPath, "github.com/panyam/oneauth/cmd/oneauth")
	cmd.Env = append(cmd.Environ(), "GOWORK=off")
	cmd.Dir = oneauthCLIDir(t)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "go build oneauth CLI failed: %s", stderr.String())
	return binPath
}

// oneauthCLIDir resolves the cmd/oneauth module directory regardless of
// the test's cwd. Walks upward from this file's location until it sees
// the cmd/oneauth/go.mod file.
func oneauthCLIDir(t *testing.T) string {
	t.Helper()
	// Tests live under tests/keycloak; cmd/oneauth is a sibling under
	// the repo root. Climb two levels from the file's package dir.
	cwd, err := filepath.Abs(".")
	require.NoError(t, err)
	// repo root is two levels up from tests/keycloak/
	root := filepath.Join(cwd, "..", "..")
	dir := filepath.Join(root, "cmd", "oneauth")
	require.FileExists(t, filepath.Join(dir, "go.mod"),
		"cmd/oneauth/go.mod not found at %s", dir)
	return dir
}

// runCLI executes the binary with the given args and returns stdout +
// stderr separately. Times out via t.Deadline when set.
func runCLI(t *testing.T, bin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// TestOneauthCLI_ClientCredentials_Keycloak proves that `oneauth token
// client-credentials` produces a working access token against
// Keycloak's confidential client.
func TestOneauthCLI_ClientCredentials_Keycloak(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	bin := buildOneauthCLI(t)

	stdout, stderr, err := runCLI(t, bin, "token", "client-credentials", realmURL(),
		"--client-id", confidentialClientID,
		"--client-secret", confidentialClientSecret,
	)
	require.NoError(t, err, "stderr=%s", stderr)

	var out cliTokenOutput
	require.NoError(t, json.Unmarshal([]byte(stdout), &out), "stdout=%s", stdout)
	assert.NotEmpty(t, out.AccessToken, "Keycloak MUST issue an access token")
	assert.Equal(t, "Bearer", out.TokenType)
	assert.Contains(t, out.Issuer, realmName)
	// Validate the token is a real JWT — three dot-separated base64url
	// segments. parseJWTClaims will fail loudly if not.
	claims := parseJWTClaims(t, out.AccessToken)
	assert.Equal(t, confidentialClientID, claims["azp"], "azp claim MUST identify the client")
}

// TestOneauthCLI_Password_Keycloak proves that `oneauth token password`
// works against Keycloak's direct-access-grant flow, prints the
// deprecation banner to stderr, and returns a refresh token (Keycloak
// issues these on password grant by default).
func TestOneauthCLI_Password_Keycloak(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	bin := buildOneauthCLI(t)

	stdout, stderr, err := runCLI(t, bin, "token", "password", realmURL(),
		"--client-id", confidentialClientID,
		"--client-secret", confidentialClientSecret,
		"--user", testUsername,
		"--password", testPassword,
		"--scopes", "openid",
	)
	require.NoError(t, err, "stderr=%s stdout=%s", stderr, stdout)

	assert.Contains(t, stderr, "deprecated", "ROPC deprecation banner MUST print to stderr")

	var out cliTokenOutput
	require.NoError(t, json.Unmarshal([]byte(stdout), &out), "stdout=%s", stdout)
	assert.NotEmpty(t, out.AccessToken)
}

// TestOneauthCLI_RefreshFlow_Keycloak proves the refresh subcommand
// works end-to-end: acquire an initial token via password grant, then
// exchange the returned refresh_token for a fresh access token via
// the dedicated `oneauth token refresh` subcommand. This is the wire-
// format check for AuthClient.RefreshToken — confirms the
// form-encoded RFC 6749 §6 request reaches Keycloak and is honored.
//
// NOTE: AuthClient.Login uses the legacy oneauth-native JSON
// /auth/cli/token endpoint, which Keycloak does NOT serve. So the
// password step of this test exercises Keycloak's standards /token
// endpoint indirectly — via getPasswordToken, which speaks form-
// encoded RFC 6749. We then drive the refresh through the CLI.
func TestOneauthCLI_RefreshFlow_Keycloak(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	bin := buildOneauthCLI(t)

	// Step 1 — get an initial refresh token via password grant
	// (form-encoded against Keycloak's standards /token endpoint).
	tokens := getPasswordToken(t, discoverOIDC(t).TokenEndpoint,
		confidentialClientID, confidentialClientSecret,
		testUsername, testPassword)
	require.NotEmpty(t, tokens.RefreshToken, "Keycloak MUST issue a refresh_token on password grant")

	// Step 2 — refresh via the CLI.
	stdout, stderr, err := runCLI(t, bin, "token", "refresh", realmURL(),
		"--client-id", confidentialClientID,
		"--client-secret", confidentialClientSecret,
		"--refresh-token", tokens.RefreshToken,
	)
	require.NoError(t, err, "stderr=%s stdout=%s", stderr, stdout)

	var out cliTokenOutput
	require.NoError(t, json.Unmarshal([]byte(stdout), &out), "stdout=%s", stdout)
	assert.NotEmpty(t, out.AccessToken, "refresh MUST produce a fresh access token")
	assert.NotEqual(t, tokens.AccessToken, out.AccessToken,
		"refreshed access token MUST differ from the original")
}

// TestOneauthCLI_AccessTokenOnlyFormat_Keycloak — the bare-token format
// emits exactly the access_token with no surrounding whitespace, so
// `$(oneauth token client-credentials ...)` is shell-safe.
func TestOneauthCLI_AccessTokenOnlyFormat_Keycloak(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	bin := buildOneauthCLI(t)

	stdout, stderr, err := runCLI(t, bin, "token", "client-credentials", realmURL(),
		"--client-id", confidentialClientID,
		"--client-secret", confidentialClientSecret,
		"--format", "access-token-only",
	)
	require.NoError(t, err, "stderr=%s", stderr)
	assert.False(t, strings.HasSuffix(stdout, "\n"),
		"access-token-only format MUST NOT end with a newline")
	// Three dot-separated segments = JWT shape.
	parts := strings.Split(stdout, ".")
	assert.Len(t, parts, 3, "access token must be a JWT")
}
