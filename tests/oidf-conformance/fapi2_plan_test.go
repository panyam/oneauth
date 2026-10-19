package oidfconformance_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/tests/oidf-conformance/fapi2"
	"github.com/panyam/oneauth/tests/oidf-conformance/harness"
)

// TestOIDF_FAPI2_SecurityProfile is the ratchet for the FAPI 2.0 mission
// (issue 98). It runs every module of the harness's
// fapi2-security-profile-final-test-plan against a cmd/oneauth-server
// started with oneauth-fapi2.yaml, and fails on each module fapi2.Judge
// finds out of line with known-gaps.yaml: a REGRESSION (a module ended
// worse than its entry allows, or failed with none) or a RATCHET-UP (an
// entry that no longer describes the run).
//
// It needs a fresh server on :8889 (`./scripts/exercise-fapi2.sh --go-test`
// starts one, as `make testoidf` does), and skips when either the harness or
// that server isn't reachable.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html
// See: https://www.rfc-editor.org/rfc/rfc9126 (PAR)
// See: https://www.rfc-editor.org/rfc/rfc9449 (DPoP)
func TestOIDF_FAPI2_SecurityProfile(t *testing.T) {
	serverURL := envOr("OIDF_FAPI2_SERVER_URL", "https://localhost:8889")
	skipIfHarnessOrFAPI2ServerNotReady(t, serverURL)

	expected, err := fapi2.LoadExpectations(filepath.Join(findWorkspaceRoot(t), "tests", "conformance", "known-gaps.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: probeTransport(t)}
	s := fapi2.Setup{
		Alias: "oneauth-fapi2", HarnessURL: harnessURL(), IssuerURL: envOr("OIDF_FAPI2_ISSUER", "https://host.docker.internal:8889"), Scope: "read",
		User: fapi2.User{Email: "fapi2-user@example.com", Password: "fapi2-exercise-password"},
	}
	ctx := context.Background()
	if err := fapi2.Prepare(ctx, hc, serverURL, &s); err != nil {
		t.Fatal(err)
	}

	planID, results, err := fapi2.RunPlan(ctx, harness.New(harnessURL()), s, 90*time.Second, "", func(r fapi2.ModuleResult) {
		t.Logf("%-8s %-26s %s", r.Result, r.Status, strings.TrimPrefix(r.Module, "fapi2-security-profile-final-"))
	})
	if err != nil {
		t.Fatalf("create the plan: %v", err)
	}
	for _, v := range fapi2.Judge(results, expected) {
		if v.Kind != fapi2.VerdictOK {
			t.Errorf("%s: %s %s", v.Kind, v.Module, v.Detail)
		}
	}
	t.Logf("%d modules, plan %s/plan-detail.html?plan=%s", len(results), harnessURL(), planID)
}

func skipIfHarnessOrFAPI2ServerNotReady(t *testing.T, serverURL string) {
	t.Helper()
	httpClient := &http.Client{Timeout: 3 * time.Second, Transport: harness.New("").HTTPClient.Transport}
	if _, err := httpClient.Get(harnessURL() + "/api/version"); err != nil {
		t.Skipf("OIDF harness not reachable at %s (run `make upoidf`): %v", harnessURL(), err)
	}
	probe := &http.Client{Timeout: 3 * time.Second, Transport: probeTransport(t)}
	if _, err := probe.Get(serverURL + "/.well-known/openid-configuration"); err != nil {
		t.Skipf("FAPI 2.0 oneauth-server not reachable at %s (run `./scripts/exercise-fapi2.sh --go-test`): %v", serverURL, err)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
