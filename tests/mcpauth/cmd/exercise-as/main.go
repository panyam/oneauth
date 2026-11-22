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
	"github.com/panyam/oneauth/testutil"
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
	genCert := flag.String("gen-cimd-cert", "", "write a self-signed cert.pem and key.pem for 127.0.0.1 into this directory, then exit")
	cimdCert := flag.String("cimd-cert", "", "cert.pem for the client ID metadata document server; empty skips the CIMD run")
	cimdKey := flag.String("cimd-key", "", "key.pem for the client ID metadata document server")
	cimdPort := flag.Int("cimd-port", 18401, "port for the client ID metadata document server")
	flag.Parse()
	if *genCert != "" {
		if err := asflow.WriteSelfSignedCert(*genCert); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *conf == "" {
		log.Fatal("-conformance is required")
	}

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if err := testutil.SignUp(hc, *asURL, "mcp-as@example.com", "mcp-as-exercise-password-1"); err != nil {
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
	fw := framework{conf: *conf, asURL: *asURL, resource: *resource, port: *port, endpoint: meta.AuthorizationEndpoint, approve: client.ApproveConsent(hc)}

	checks := fw.run(clientID, "")
	if *cimdCert != "" {
		// The second run logs in as a client with no registration: its
		// client_id is the URL of a metadata document this command serves
		// (issue 532). Its checks get a "cimd-" prefix.
		docURL := fmt.Sprintf("https://127.0.0.1:%d/mcp-conformance-client.json", *cimdPort)
		stop, err := asflow.ServeClientMetadata(fmt.Sprintf("127.0.0.1:%d", *cimdPort), *cimdCert, *cimdKey,
			asflow.ClientMetadataDocument(docURL, redirect))
		if err != nil {
			log.Fatalf("serve the client metadata document: %v", err)
		}
		defer stop()
		checks = append(checks, fw.run(docURL, CIMDPrefix)...)
	}

	expected, err := judge.LoadExpectations(*manifest, Plan)
	if err != nil {
		log.Fatal(err)
	}
	rec := judge.NewPlanRecord(Plan, judge.Merge(checks), expected)
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

// CIMDPrefix marks the checks of the run whose client_id is a metadata
// document URL, so they don't merge with the registered client's.
const CIMDPrefix = "cimd-"

// framework runs the conformance framework's `authorization` command.
type framework struct {
	conf, asURL, resource, endpoint string
	port                            int
	approve                         func(string) error
}

// run runs every scenario as clientID, approving each authorization URL
// the command prints, and returns the checks with prefix on their ids. A
// scenario that wrote no checks.json is one failed check named after it,
// so the run can't pass without it.
func (fw framework) run(clientID, prefix string) []judge.Check {
	out, err := os.MkdirTemp("", Plan+"-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(out)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// node with tsx as a loader runs the framework in one process. Through
	// npx, tsx starts a child, and cancelling killed only the parent, so the
	// child kept stdout open through its 5-minute callback wait.
	cmd := exec.CommandContext(ctx, "node", "--import", "tsx", "src/index.ts", "authorization",
		"--url", fw.asURL, "--client-id", clientID, "--resource", fw.resource,
		"--port", fmt.Sprint(fw.port), "--output-dir", out)
	cmd.Dir = fw.conf
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("start the framework: %v", err)
	}
	urls, approveErr := asflow.Watch(stdout, os.Stdout, fw.endpoint, func(u string) error {
		if err := fw.approve(u); err != nil {
			cancel()
			return err
		}
		return nil
	})
	runErr := cmd.Wait()
	if approveErr != nil {
		log.Printf("approving an authorization request failed: %v", approveErr)
	}
	fmt.Printf("\napproved %d authorization request(s) as %s; framework exit: %v\n\n", len(urls), clientID, runErr)

	var all []judge.Check
	for _, s := range Scenarios {
		checks, err := readScenario(out, s)
		if err != nil {
			msg := fmt.Sprintf("no checks (%v)", err)
			if approveErr != nil {
				msg += "; approval: " + approveErr.Error()
			}
			checks = []judge.Check{{ID: s, Status: judge.Failure, ErrorMessage: msg}}
		}
		for _, c := range checks {
			c.ID = prefix + c.ID
			all = append(all, c)
		}
	}
	return all
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
