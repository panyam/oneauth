// Command exercise-jarm runs the JARM mission's exercise (issue 409): a
// headless `oneauth token browser --response-mode jwt` login against a
// oneauth-server and against the test Keycloak realm.
//
// For each target it runs the CLI with --no-browser, reads the
// authorization URL from its stderr, and logs in the way a person would:
// client.ApproveConsent for oneauth-server, after testutil.SignUp, and
// testutil.KeycloakPasswordLogin for Keycloak. The login's HTTP client
// watches the redirect to the CLI's loopback callback go by. When the
// callback carries a JARM `response`, the driver decodes the JWT without
// verifying it and prints its header and claims. Then the CLI gets the
// callback and prints a token, or the reason it refused.
//
// scripts/exercise-jarm.sh builds the binaries, starts the server and runs
// this. It exits 1 when any target fails to end with an access token.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/testutil"
)

func main() {
	cli := flag.String("cli", "oneauth", "path to the oneauth CLI")
	asURL := flag.String("as", "http://localhost:18500", "oneauth-server issuer; empty skips it")
	kcIssuer := flag.String("keycloak", "http://localhost:8180/realms/oneauth-test", "Keycloak realm issuer; empty skips it")
	kcClient := flag.String("keycloak-client", "test-jarm", "Keycloak client_id")
	kcUser := flag.String("keycloak-user", "testuser", "Keycloak username")
	kcPassword := flag.String("keycloak-password", "testpassword", "Keycloak password")
	port := flag.Int("callback-port", 18501, "loopback callback port the CLI listens on")
	mode := flag.String("response-mode", "jwt", "response_mode to request")
	flag.Parse()

	r := runner{cli: *cli, port: *port, mode: *mode}
	var results []string
	failed := false
	if *asURL != "" {
		ok, summary := r.oneauth(*asURL)
		failed = failed || !ok
		results = append(results, "oneauth-server: "+summary)
	}
	if *kcIssuer != "" {
		ok, summary := r.keycloak(*kcIssuer, *kcClient, *kcUser, *kcPassword)
		failed = failed || !ok
		results = append(results, "keycloak:       "+summary)
	}
	fmt.Println("\n== result")
	for _, line := range results {
		fmt.Println(line)
	}
	if failed {
		os.Exit(1)
	}
}

type runner struct {
	cli  string
	port int
	mode string
}

// redirectURI is the redirect URI the CLI sends for --callback-port, as
// client.LoopbackRedirectURI builds it.
func (r runner) redirectURI() string {
	return fmt.Sprintf("http://localhost:%d/callback", r.port)
}

// oneauth signs a user up, registers a public loopback client through open
// DCR, and logs in with consent approved.
func (r runner) oneauth(asURL string) (bool, string) {
	fmt.Printf("== oneauth-server at %s, response_mode=%s\n", asURL, r.mode)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	email := fmt.Sprintf("jarm-%d@example.com", time.Now().UnixNano())
	if err := testutil.SignUp(hc, asURL, email, "jarm-exercise-password-1"); err != nil {
		return false, "could not sign up: " + err.Error()
	}
	clientID, err := testutil.RegisterClient(hc, asURL+"/apps/dcr", map[string]any{
		"client_name":                "JARM exercise",
		"redirect_uris":              []string{r.redirectURI()},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	if err != nil {
		return false, "could not register a client: " + err.Error()
	}
	fmt.Printf("registered client %s\n", clientID)
	hc.Transport = r.watch(http.DefaultTransport)
	return r.login(asURL, clientID, client.ApproveConsent(hc))
}

// keycloak logs in to the test realm's JARM client through its login form.
func (r runner) keycloak(issuer, clientID, user, password string) (bool, string) {
	fmt.Printf("\n== keycloak at %s, client %s, response_mode=%s\n", issuer, clientID, r.mode)
	hc := &http.Client{Timeout: 30 * time.Second, Transport: r.watch(http.DefaultTransport)}
	return r.login(issuer, clientID, testutil.KeycloakPasswordLogin(hc, user, password))
}

// login runs the CLI and hands the authorization URL it prints to open.
// It reports whether the CLI printed an access token, with a one-line
// summary: the token's type and scope, or the CLI's last error line.
func (r runner) login(issuer, clientID string, open func(string) error) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"token", "browser", issuer,
		"--client-id", clientID, "--no-browser", "--timeout", "30s",
		"--callback-port", strconv.Itoa(r.port), "--format", "json"}
	if r.mode != "" {
		args = append(args, "--response-mode", r.mode)
	}
	fmt.Printf("$ oneauth %s\n", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, r.cli, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return false, err.Error()
	}
	if err := cmd.Start(); err != nil {
		return false, "could not start the CLI: " + err.Error()
	}

	var lastErr string
	var openErr error
	var wg sync.WaitGroup
	sc := bufio.NewScanner(stderr)
	for sc.Scan() {
		line := sc.Text()
		fmt.Println("  cli: " + line)
		if strings.TrimSpace(line) != "" {
			lastErr = strings.TrimSpace(line)
		}
		u := strings.TrimSpace(line)
		if strings.HasPrefix(u, "http") && strings.Contains(u, "client_id=") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := open(u); err != nil {
					openErr = err
					fmt.Printf("  login: %v\n", err)
					cancel()
				}
			}()
		}
	}
	runErr := cmd.Wait()
	wg.Wait()

	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if runErr == nil && json.Unmarshal(stdout.Bytes(), &tok) == nil && tok.AccessToken != "" {
		fmt.Printf("  cli stdout: %s\n", strings.TrimSpace(stdout.String()))
		return true, fmt.Sprintf("PASS: %s access token, scope %q", tok.TokenType, tok.Scope)
	}
	switch {
	case openErr != nil:
		return false, "FAIL: login: " + openErr.Error()
	case lastErr != "":
		return false, "FAIL: " + lastErr
	default:
		return false, fmt.Sprintf("FAIL: %v", runErr)
	}
}

// watch wraps rt so every request to the CLI's loopback callback gets
// printed before it is delivered.
func (r runner) watch(rt http.RoundTripper) http.RoundTripper {
	hosts := map[string]bool{
		"localhost:" + strconv.Itoa(r.port): true,
		"127.0.0.1:" + strconv.Itoa(r.port): true,
	}
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if hosts[req.URL.Host] {
			printCallback(req.URL.Query())
		}
		return rt.RoundTrip(req)
	})
}

// printCallback prints the authorization response on the callback: the
// decoded JARM JWT when there is one, and the plain parameters otherwise.
func printCallback(q url.Values) {
	jwt := q.Get("response")
	if jwt == "" {
		fmt.Println("  callback: unsigned response (no `response` parameter)")
		for _, k := range []string{"error", "error_description", "code", "state", "iss"} {
			if v := q.Get(k); v != "" {
				fmt.Printf("    %s=%s\n", k, abbreviate(k, v))
			}
		}
		return
	}
	fmt.Println("  callback: signed response (JARM), decoded without verification")
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		fmt.Printf("    not a JWS: %d parts\n", len(parts))
		return
	}
	for i, name := range []string{"header", "claims"} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			fmt.Printf("    %s: not base64url: %v\n", name, err)
			continue
		}
		var pretty bytes.Buffer
		if json.Indent(&pretty, raw, "    ", "  ") != nil {
			pretty.Write(raw)
		}
		fmt.Printf("    %s: %s\n", name, pretty.String())
	}
	if exp := claimsExp(parts[1]); !exp.IsZero() {
		fmt.Printf("    exp is %s from now\n", time.Until(exp).Round(time.Second))
	}
}

// abbreviate shortens a code so the output doesn't hand one out whole.
func abbreviate(key, v string) string {
	if key == "code" && len(v) > 8 {
		return v[:8] + "..."
	}
	return v
}

func claimsExp(seg string) time.Time {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return time.Time{}
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(c.Exp, 0)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
