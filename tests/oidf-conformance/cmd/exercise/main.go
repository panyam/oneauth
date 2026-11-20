// Command exercise runs one OIDF conformance plan against a running
// cmd/oneauth-server: it registers the plan's user and clients, creates the
// plan in a running harness, runs every module, and prints one line per
// module. -plan picks the plan:
//
//	fapi2    fapi2-security-profile-final-test-plan (mission 98)
//	oidcc    oidcc-basic-certification-test-plan (mission 477)
//	oidccfp  oidcc-formpost-basic-certification-test-plan (issue 500)
//	oidcci   oidcc-implicit-certification-test-plan (issue 526)
//	oidccfpi oidcc-formpost-implicit-certification-test-plan (issue 526)
//	oidcdyn  oidcc-dynamic-certification-test-plan (issue 493)
//	oidcctp  oidcc-test-plan with -auth's client auth method (issue 494)
//
// `make exercise-fapi2` and `make exercise-oidcc` start the harness and a
// server and run this; see scripts/exercise-oidf.sh. Each module is judged
// against its entry in tests/conformance/known-gaps.yaml (oidfplan.Judge),
// and the command exits 1 on any REGRESSION or RATCHET-UP, the same
// verdicts that fail the plan's go test in `make testoidf`.
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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/panyam/oneauth/tests/oidf-conformance/fapi2"
	"github.com/panyam/oneauth/tests/oidf-conformance/harness"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidcc"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidcdyn"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
)

func main() {
	planFlag := flag.String("plan", "fapi2", "plan to run: fapi2, oidcc, oidccfp, oidcci, oidccfpi, oidcdyn or oidcctp")
	authType := flag.String("auth", "", "oidcctp only: the client auth method to run oidcc-test-plan with")
	responseType := flag.String("response-type", "", "oidcdyn only: an implicit response type to run the Dynamic plan with instead of code")
	harnessURL := flag.String("harness", "https://localhost.emobix.co.uk:8443", "OIDF harness origin")
	serverURL := flag.String("server", "https://localhost:8889", "oneauth-server as this machine reaches it")
	issuerURL := flag.String("issuer", "https://host.docker.internal:8889", "oneauth-server as the harness container reaches it (its public_url)")
	caFile := flag.String("ca", "certs/ca.crt", "CA that signed the server's TLS certificate")
	alias := flag.String("alias", "", "plan alias, which also forms the redirect URI (default oneauth-<plan>)")
	manifest := flag.String("manifest", "../conformance/known-gaps.yaml", "known-gaps.yaml the run is judged against")
	only := flag.String("module", "", "run only the modules whose names contain this")
	perModule := flag.Duration("module-timeout", 90*time.Second, "how long one module may run")
	flag.Parse()

	if *alias == "" {
		*alias = "oneauth-" + *planFlag
		if *authType != "" {
			*alias += "-" + strings.ReplaceAll(*authType, "_", "-")
		}
		if *responseType != "" {
			*alias += "-" + strings.ReplaceAll(*responseType, " ", "-")
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

	var plan oidfplan.Plan
	var prefix string
	switch *planFlag {
	case "fapi2":
		s := fapi2.Setup{
			Alias: *alias, HarnessURL: *harnessURL, IssuerURL: *issuerURL, Scope: "openid read",
			User: oidfplan.User{Email: "fapi2-user@example.com", Password: "fapi2-exercise-password", Profile: oidfplan.StandardProfile()},
		}
		if err := fapi2.Prepare(ctx, hc, *serverURL, &s); err != nil {
			log.Fatal(err)
		}
		for i, c := range s.Clients {
			fmt.Printf("registered client %d: %s\n", i+1, c.ID)
		}
		plan, prefix = fapi2.Plan(s), "fapi2-security-profile-final-"
	case "oidcc", "oidccfp":
		s := oidcc.Setup{
			Alias: *alias, HarnessURL: *harnessURL, IssuerURL: *issuerURL, Scope: oidcc.Scope,
			User: oidcc.ExerciseUser(),
		}
		if err := oidcc.Prepare(ctx, hc, *serverURL, &s); err != nil {
			log.Fatal(err)
		}
		for i, c := range s.Clients {
			fmt.Printf("registered client %d: %s\n", i+1, c.ID)
		}
		fmt.Printf("registered client_secret_post client: %s\n", s.PostClient.ID)
		plan, prefix = oidcc.Plan(s), oidcc.ModulePrefix
		if *planFlag == "oidccfp" {
			plan = oidcc.FormPostPlan(s)
		}
	case "oidcci", "oidccfpi":
		s := oidcc.Setup{
			Alias: *alias, HarnessURL: *harnessURL, IssuerURL: *issuerURL, Scope: oidcc.Scope,
			User: oidcc.ExerciseUser(),
		}
		if err := oidcc.PrepareImplicit(ctx, hc, *serverURL, &s); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("registered implicit client: %s\n", s.Clients[0].ID)
		plan, prefix = oidcc.ImplicitPlan(s), oidcc.ModulePrefix
		if *planFlag == "oidccfpi" {
			plan = oidcc.FormPostImplicitPlan(s)
		}
	case "oidcdyn", "oidcctp":
		s := oidcdyn.Setup{Alias: *alias, HarnessURL: *harnessURL, IssuerURL: *issuerURL, User: oidcdyn.ExerciseUser()}
		if err := oidfplan.SignUp(ctx, hc, *serverURL, s.User); err != nil {
			log.Fatalf("sign up the browser user: %v", err)
		}
		plan, prefix = oidcdyn.DynamicPlan(s), oidcc.ModulePrefix
		if *planFlag == "oidcdyn" && *responseType != "" {
			if plan, err = oidcdyn.DynamicImplicitPlan(s, *responseType); err != nil {
				log.Fatal(err)
			}
		}
		if *planFlag == "oidcctp" {
			if plan, err = oidcdyn.TestPlan(s, *authType); err != nil {
				log.Fatal(err)
			}
		}
	default:
		log.Fatalf("unknown -plan %q: want fapi2, oidcc, oidccfp, oidcci, oidccfpi, oidcdyn or oidcctp", *planFlag)
	}

	expected, err := oidfplan.LoadExpectations(*manifest, plan.ManifestKey())
	if err != nil {
		log.Fatal(err)
	}
	for m := range expected {
		if !strings.Contains(m, *only) {
			delete(expected, m)
		}
	}
	plan.Manual = oidfplan.ManualModules(expected)
	plan.Actions = map[string]func(context.Context) error{
		"oidcc-server-rotate-keys": oidfplan.RotateServerKeys(hc, *serverURL),
	}

	h := harness.New(*harnessURL)
	fmt.Printf("\n%s (%s)\n", plan.ManifestKey(), variantString(plan.Variant))
	planID, results, err := oidfplan.RunPlan(ctx, h, plan, *perModule, *only, func(r oidfplan.ModuleResult) {
		one := map[string]oidfplan.Expectation{}
		if e, ok := expected[r.Module]; ok {
			one[r.Module] = e
		}
		v := oidfplan.Judge([]oidfplan.ModuleResult{r}, one)[0]
		mark := ""
		if v.Kind != oidfplan.VerdictOK {
			mark = string(v.Kind)
		}
		fmt.Printf("  %-8s %-26s %-11s %s\n", orDash(r.Result), r.Status, mark, strings.TrimPrefix(r.Module, prefix))
		if v.Detail != "" {
			fmt.Printf("           %s\n", v.Detail)
		}
		if r.ReviewPage != "" {
			fmt.Printf("           page: %.200s\n", pageText(r.ReviewPage))
		}
		if r.FirstFailure != "" {
			fmt.Printf("           %.200s\n", r.FirstFailure)
		}
		if r.Result == "WARNING" && len(r.Warnings) > 0 {
			fmt.Printf("           warning: %.200s\n", r.Warnings[0])
		}
		if r.Err != nil {
			fmt.Printf("           %v\n", r.Err)
		}
	})
	if err != nil {
		log.Fatalf("create the plan: %v", err)
	}

	rec := oidfplan.NewPlanRecord(plan, planID, results, expected)
	for _, m := range rec.Modules {
		if m.Verdict != string(oidfplan.VerdictOK) && !ran(results, m.Module) {
			fmt.Printf("  %s %s: %s\n", m.Verdict, m.Module, m.Note)
		}
	}
	// `make conformance` sets CONFORMANCE_RESULTS_DIR and reads the record
	// back for the committed conformance report.
	if dir := os.Getenv("CONFORMANCE_RESULTS_DIR"); dir != "" {
		if err := oidfplan.WritePlanRecord(filepath.Join(dir, plan.ManifestKey()+".json"), rec); err != nil {
			log.Printf("write the run record: %v", err)
		}
	}
	bad := rec.Against
	fmt.Printf("\n%d modules: %v, %d against known-gaps.yaml\nplan: %s/plan-detail.html?plan=%s\n", len(results), rec.Counts, bad, *harnessURL, planID)
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

func ran(results []oidfplan.ModuleResult, module string) bool {
	for _, r := range results {
		if r.Module == module {
			return true
		}
	}
	return false
}

func variantString(variant map[string]string) string {
	var parts []string
	for k, v := range variant {
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
