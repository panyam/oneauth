// Command exercise runs the MCP server-auth conformance scenarios against a
// running fixture and judges them against tests/conformance/known-gaps.yaml
// (issue 495). scripts/exercise-mcpauth.sh starts oneauth-server and the
// fixture, then runs this.
//
// It runs driver/run-auth.ts with `npx tsx` in the framework checkout, with
// the fixture's tokens in the AUTH_* variables the scenarios read, and reads
// back the checks.json it writes for each scenario. Every check across the
// scenarios is judged as one plan, "mcp-auth-<sdk>". The run record goes to
// $CONFORMANCE_RESULTS_DIR when `make conformance` sets it, and the exit
// status is 1 when any check is against the manifest.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/panyam/oneauth/tests/mcpauth/fixture"
	"github.com/panyam/oneauth/tests/mcpauth/judge"
)

// Scenarios are the framework's server auth scenarios, in its order.
var Scenarios = []string{
	"auth-oauth-discovery",
	"auth-jwt-validation",
	"auth-jwt-claims",
	"auth-scope-step-up",
	"auth-iss-param",
	"auth-enterprise-managed",
}

func main() {
	sdk := flag.String("sdk", "", "fixture SDK: gosdk or mcpkit; the plan is mcp-auth-<sdk>")
	conf := flag.String("conformance", "", "the conformance framework checkout")
	fixtureURL := flag.String("fixture", "http://localhost:18300", "the fixture's base URL, which serves /demo/bootstrap")
	asURL := flag.String("as", "http://localhost:18200", "oneauth-server's issuer URL")
	manifest := flag.String("manifest", "../conformance/known-gaps.yaml", "known-gaps.yaml")
	driver := flag.String("driver", "driver/run-auth.ts", "the scenario driver script")
	flag.Parse()
	if *sdk == "" || *conf == "" {
		log.Fatal("-sdk and -conformance are required")
	}
	plan := "mcp-auth-" + *sdk

	var tokens fixture.Tokens
	if err := getJSON(*fixtureURL+"/demo/bootstrap", &tokens); err != nil {
		log.Fatalf("read the fixture's tokens: %v", err)
	}
	var asMeta struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := getJSON(*asURL+"/.well-known/oauth-authorization-server", &asMeta); err != nil {
		log.Fatalf("read the AS metadata: %v", err)
	}
	env := append(os.Environ(),
		"AUTH_SERVER_URL="+tokens.MCPURL,
		"AUTH_VALID_TOKEN="+tokens.TokRead,
		"AUTH_READWRITE_TOKEN="+tokens.TokReadWrite,
		"AUTH_FULL_TOKEN="+tokens.TokAll,
		"AUTH_EXPIRED_TOKEN="+tokens.TokExpired,
		"AUTH_WRONG_AUDIENCE_TOKEN="+tokens.TokWrongAud,
		"AUTH_WRONG_ISSUER_TOKEN="+tokens.TokWrongIssuer,
		"AUTH_AS_TOKEN_ENDPOINT="+asMeta.TokenEndpoint,
		"AUTH_SUBJECT_ASSERTION_TOKEN="+tokens.TokUpstreamAssertion,
	)

	out, err := os.MkdirTemp("", plan+"-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(out)
	all := runScenarios(*conf, *driver, out, tokens.MCPURL, env)
	checks := judge.Merge(all...)
	expected, err := judge.LoadExpectations(*manifest, plan)
	if err != nil {
		log.Fatal(err)
	}
	rec := judge.NewPlanRecord(plan, checks, expected)
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
		if err := rec.Write(filepath.Join(dir, plan+".json")); err != nil {
			log.Printf("write the run record: %v", err)
		}
	}
	fmt.Printf("\n%s\n", rec.Summary())
	if rec.Against > 0 {
		os.Exit(1)
	}
}

// runScenarios runs every scenario through driver/run-auth.ts, which calls
// each one's run(url) the way the framework's own auth.test.ts does, and
// returns each scenario's checks. A scenario that wrote no checks.json is
// one failed check named after it, so the run can't pass without it.
func runScenarios(conf, driver, out, mcpURL string, env []string) [][]judge.Check {
	args := append([]string{"tsx", driver, conf, mcpURL, out}, Scenarios...)
	cmd := exec.Command("npx", args...)
	cmd.Dir, cmd.Env = conf, env
	output, runErr := cmd.CombinedOutput()
	var all [][]judge.Check
	for _, s := range Scenarios {
		checks, err := judge.ReadChecks(filepath.Join(out, s, "checks.json"))
		if err != nil {
			checks = []judge.Check{{ID: s, Status: judge.Failure, ErrorMessage: fmt.Sprintf("no checks (%v): %s", runErr, tail(string(output), 400))}}
		}
		all = append(all, checks)
	}
	return all
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
	return tail(s, 240)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
