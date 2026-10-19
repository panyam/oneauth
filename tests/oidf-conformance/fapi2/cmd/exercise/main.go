// Command exercise runs the FAPI 2.0 mission's exercise (issue 98): it
// registers two clients and a user with a running cmd/oneauth-server,
// creates the OIDF fapi2-security-profile-final-test-plan in a running
// harness, runs every module, and prints one line per module.
//
// `make exercise-fapi2` starts the harness and the server and runs this;
// see scripts/exercise-fapi2.sh. Each module is judged against its entry in
// tests/conformance/known-gaps.yaml (fapi2.Judge), and the command exits 1
// on any REGRESSION or RATCHET-UP, the same verdicts that fail
// TestOIDF_FAPI2_SecurityProfile.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/panyam/oneauth/tests/oidf-conformance/fapi2"
	"github.com/panyam/oneauth/tests/oidf-conformance/harness"
)

func main() {
	harnessURL := flag.String("harness", "https://localhost.emobix.co.uk:8443", "OIDF harness origin")
	serverURL := flag.String("server", "https://localhost:8889", "oneauth-server as this machine reaches it")
	issuerURL := flag.String("issuer", "https://host.docker.internal:8889", "oneauth-server as the harness container reaches it (its public_url)")
	caFile := flag.String("ca", "certs/ca.crt", "CA that signed the server's TLS certificate")
	alias := flag.String("alias", "oneauth-fapi2", "plan alias; also forms the redirect URI")
	manifest := flag.String("manifest", "../conformance/known-gaps.yaml", "known-gaps.yaml the run is judged against")
	only := flag.String("module", "", "run only the modules whose names contain this")
	perModule := flag.Duration("module-timeout", 90*time.Second, "how long one module may run")
	flag.Parse()

	expected, err := fapi2.LoadExpectations(*manifest)
	if err != nil {
		log.Fatal(err)
	}
	for m := range expected {
		if !strings.Contains(m, *only) {
			delete(expected, m)
		}
	}
	ca, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	ctx := context.Background()

	s := fapi2.Setup{
		Alias: *alias, HarnessURL: *harnessURL, IssuerURL: *issuerURL, Scope: "read",
		User: fapi2.User{Email: "fapi2-user@example.com", Password: "fapi2-exercise-password"},
	}
	if err := fapi2.Prepare(ctx, hc, *serverURL, &s); err != nil {
		log.Fatal(err)
	}
	for i, c := range s.Clients {
		fmt.Printf("registered client %d: %s\n", i+1, c.ID)
	}

	h := harness.New(*harnessURL)
	fmt.Printf("\n%s (%s)\n", fapi2.PlanName, variantString())
	planID, results, err := fapi2.RunPlan(ctx, h, s, *perModule, *only, func(r fapi2.ModuleResult) {
		one := map[string]fapi2.Expectation{}
		if e, ok := expected[r.Module]; ok {
			one[r.Module] = e
		}
		v := fapi2.Judge([]fapi2.ModuleResult{r}, one)[0]
		mark := ""
		if v.Kind != fapi2.VerdictOK {
			mark = string(v.Kind)
		}
		fmt.Printf("  %-8s %-26s %-11s %s\n", orDash(r.Result), r.Status, mark, strings.TrimPrefix(r.Module, "fapi2-security-profile-final-"))
		if v.Detail != "" {
			fmt.Printf("           %s\n", v.Detail)
		}
		if r.ReviewPage != "" {
			fmt.Printf("           page: %.200s\n", pageText(r.ReviewPage))
		}
		if r.FirstFailure != "" {
			fmt.Printf("           %.200s\n", r.FirstFailure)
		}
		if r.Err != nil {
			fmt.Printf("           %v\n", r.Err)
		}
	})
	if err != nil {
		log.Fatalf("create the plan: %v", err)
	}

	counts := map[string]int{}
	for _, r := range results {
		counts[orDash(r.Result)]++
	}
	bad := 0
	for _, v := range fapi2.Judge(results, expected) {
		if v.Kind != fapi2.VerdictOK {
			bad++
			if !ran(results, v.Module) {
				fmt.Printf("  %s %s: %s\n", v.Kind, v.Module, v.Detail)
			}
		}
	}
	fmt.Printf("\n%d modules: %v, %d against known-gaps.yaml\nplan: %s/plan-detail.html?plan=%s\n", len(results), counts, bad, *harnessURL, planID)
	if bad > 0 {
		os.Exit(1)
	}
}

var tag = regexp.MustCompile(`<[^>]*>`)

// pageText flattens a captured page to its visible text for one line of
// output.
func pageText(html string) string {
	return strings.Join(strings.Fields(tag.ReplaceAllString(html, " ")), " ")
}

func ran(results []fapi2.ModuleResult, module string) bool {
	for _, r := range results {
		if r.Module == module {
			return true
		}
	}
	return false
}

func variantString() string {
	var parts []string
	for k, v := range fapi2.PlanVariant() {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
