// Command exercise runs the FAPI 2.0 mission's exercise (issue 98): it
// registers two clients and a user with a running cmd/oneauth-server,
// creates the OIDF fapi2-security-profile-final-test-plan in a running
// harness, runs every module, and prints one line per module.
//
// `make exercise-fapi2` starts the harness and the server and runs this;
// see scripts/exercise-fapi2.sh. It exits 1 when any module didn't pass.
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
	perModule := flag.Duration("module-timeout", 90*time.Second, "how long one module may run")
	flag.Parse()

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
	if err := fapi2.SignUp(ctx, hc, *serverURL, s.User); err != nil {
		log.Fatalf("step 1, sign up the browser user: %v", err)
	}
	for i := range s.Clients {
		key, err := fapi2.NewClientKey()
		if err != nil {
			log.Fatal(err)
		}
		id, err := fapi2.Register(ctx, hc, *serverURL, key, fapi2.ClientRedirectURI(*harnessURL, *alias, i), s.Scope)
		if err != nil {
			log.Fatalf("step 2, register client %d: %v", i+1, err)
		}
		s.Clients[i] = fapi2.RegisteredClient{ID: id, Key: key}
		fmt.Printf("registered client %d: %s\n", i+1, id)
	}

	h := harness.New(*harnessURL)
	fmt.Printf("\n%s (%s)\n", fapi2.PlanName, variantString())
	planID, results, err := fapi2.RunPlan(ctx, h, s, *perModule, func(r fapi2.ModuleResult) {
		fmt.Printf("  %-8s %-26s %s\n", orDash(r.Result), r.Status, strings.TrimPrefix(r.Module, "fapi2-security-profile-final-"))
		if r.FirstFailure != "" {
			fmt.Printf("           %.200s\n", r.FirstFailure)
		}
		if r.Err != nil {
			fmt.Printf("           %v\n", r.Err)
		}
	})
	if err != nil {
		log.Fatalf("step 3, create the plan: %v", err)
	}

	counts := map[string]int{}
	for _, r := range results {
		counts[orDash(r.Result)]++
	}
	fmt.Printf("\n%d modules: %v\nplan: %s/plan-detail.html?plan=%s\n", len(results), counts, *harnessURL, planID)
	if counts["PASSED"] != len(results) {
		os.Exit(1)
	}
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
