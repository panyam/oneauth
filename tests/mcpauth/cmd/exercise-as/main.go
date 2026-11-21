// Command exercise-as runs the MCP conformance framework's authorization
// server scenarios against a running oneauth-server, and judges them against
// tests/conformance/known-gaps.yaml as the plan "mcp-auth-as" (issue 496).
// scripts/exercise-mcpauth.sh starts the server, then runs this.
//
// It signs up a user, registers a public PKCE client whose redirect URI is
// the framework's callback, and runs the framework's own `authorization`
// command. The command prints an authorization URL for each code-flow
// scenario. asflow.Watch approves each one with client.ApproveConsent on the
// signed-in cookie jar. An approval that fails stops the command, rather than
// leaving the scenario to wait out its five minutes.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/tests/mcpauth/asflow"
	"github.com/panyam/oneauth/tests/mcpauth/judge"
)

// Plan names the run in known-gaps.yaml and in its run record.
const Plan = "mcp-auth-as"

// Scenarios are the framework's authorization-server scenarios, in its
// order. The code-flow scenarios read the metadata the first one fetched.
var Scenarios = []string{
	"authorization-server-metadata-endpoint",
	"authorization-code-grant",
	"dpop",
}

func main() {
	conf := flag.String("conformance", "", "the conformance framework checkout")
	asURL := flag.String("as", "http://localhost:18200", "oneauth-server's issuer URL")
	resource := flag.String("resource", "http://localhost:18300/mcp", "the MCP server the tokens are for (RFC 8707 resource)")
	port := flag.Int("port", 18400, "port for the framework's callback server")
	manifest := flag.String("manifest", "../conformance/known-gaps.yaml", "known-gaps.yaml")
	flag.Parse()
	if *conf == "" {
		log.Fatal("-conformance is required")
	}

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if err := asflow.SignUp(hc, *asURL, "mcp-as@example.com", "mcp-as-exercise-password-1"); err != nil {
		log.Fatalf("sign up the exercise user: %v", err)
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", *port)
	clientID, err := asflow.Register(&http.Client{Timeout: 30 * time.Second}, *asURL, redirect)
	if err != nil {
		log.Fatalf("register the exercise client: %v", err)
	}
	var meta struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
	}
	if err := getJSON(*asURL+"/.well-known/oauth-authorization-server", &meta); err != nil {
		log.Fatalf("read the AS metadata: %v", err)
	}

	out, err := os.MkdirTemp("", Plan+"-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(out)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "npx", "tsx", "src/index.ts", "authorization",
		"--url", *asURL, "--client-id", clientID, "--resource", *resource,
		"--port", fmt.Sprint(*port), "--output-dir", out)
	cmd.Dir = *conf
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("start the framework: %v", err)
	}
	approve := client.ApproveConsent(hc)
	urls, approveErr := asflow.Watch(stdout, os.Stdout, meta.AuthorizationEndpoint, func(u string) error {
		if err := approve(u); err != nil {
			cancel()
			return err
		}
		return nil
	})
	runErr := cmd.Wait()
	if approveErr != nil {
		log.Printf("approving an authorization request failed: %v", approveErr)
	}
	fmt.Printf("\napproved %d authorization request(s); framework exit: %v\n\n", len(urls), runErr)

	var all [][]judge.Check
	for _, s := range Scenarios {
		checks, err := readScenario(out, s)
		if err != nil {
			msg := fmt.Sprintf("no checks (%v)", err)
			if approveErr != nil {
				msg += "; approval: " + approveErr.Error()
			}
			checks = []judge.Check{{ID: s, Status: judge.Failure, ErrorMessage: msg}}
		}
		all = append(all, checks)
	}
	checks := judge.Merge(all...)
	expected, err := judge.LoadExpectations(*manifest, Plan)
	if err != nil {
		log.Fatal(err)
	}
	rec := judge.NewPlanRecord(Plan, checks, expected)
	for _, m := range rec.Modules {
		mark := "  "
		if m.Verdict != judge.OK {
			mark = m.Verdict + " "
		}
		fmt.Printf("%-8s %s%s\n", m.Result, mark, m.Module)
		if m.Note != "" && m.Result != judge.Success {
			fmt.Printf("           %s\n", firstLine(m.Note))
		}
	}
	if dir := os.Getenv("CONFORMANCE_RESULTS_DIR"); dir != "" {
		if err := rec.Write(filepath.Join(dir, Plan+".json")); err != nil {
			log.Printf("write the run record: %v", err)
		}
	}
	fmt.Printf("\n%s\n", rec.Summary())
	if rec.Against > 0 {
		os.Exit(1)
	}
}

// readScenario reads the checks.json the framework wrote for scenario. Its
// directory is "authorization-server-<scenario>-<timestamp>", and the
// newest one wins.
func readScenario(out, scenario string) ([]judge.Check, error) {
	matches, _ := filepath.Glob(filepath.Join(out, "authorization-server-"+scenario+"-*", "checks.json"))
	// "authorization-code-grant-*" must not match another scenario whose
	// name extends it, so keep only a timestamp after the name.
	var mine []string
	for _, m := range matches {
		rest := strings.TrimPrefix(filepath.Base(filepath.Dir(m)), "authorization-server-"+scenario+"-")
		if rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			mine = append(mine, m)
		}
	}
	if len(mine) == 0 {
		return nil, fmt.Errorf("the framework wrote no checks.json for %s", scenario)
	}
	sort.Strings(mine)
	return judge.ReadChecks(mine[len(mine)-1])
}

func getJSON(url string, out any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 240 {
		return "…" + s[len(s)-240:]
	}
	return s
}
