package oidfconformance_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/tests/oidf-conformance/harness"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidcc"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
)

// TestOIDF_OIDCC_BasicOP is the ratchet for mission 477. It runs every
// module of the harness's oidcc-basic-certification-test-plan against a
// cmd/oneauth-server started with oneauth-oidcc.yaml, and fails on each
// module oidfplan.Judge finds out of line with known-gaps.yaml: a
// REGRESSION or a RATCHET-UP, as for the FAPI 2.0 plan.
//
// It needs a fresh server on :8890 (`./scripts/exercise-oidf.sh oidcc
// --go-test` starts one, as `make testoidf` does), and skips when either
// the harness or that server isn't reachable.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html
// See: https://openid.net/certification/
func TestOIDF_OIDCC_BasicOP(t *testing.T) {
	serverURL := envOr("OIDF_OIDCC_SERVER_URL", "https://localhost:8890")
	skipIfHarnessOrServerNotReady(t, serverURL, "OIDC Basic OP", "./scripts/exercise-oidf.sh oidcc --go-test")

	expected, err := oidfplan.LoadExpectations(filepath.Join(findWorkspaceRoot(t), "tests", "conformance", "known-gaps.yaml"), oidcc.PlanName)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: probeTransport(t)}
	s := oidcc.Setup{
		Alias: "oneauth-oidcc", HarnessURL: harnessURL(), IssuerURL: envOr("OIDF_OIDCC_ISSUER", "https://host.docker.internal:8890"), Scope: oidcc.Scope,
		User: oidcc.ExerciseUser(),
	}
	ctx := context.Background()
	if err := oidcc.Prepare(ctx, hc, serverURL, &s); err != nil {
		t.Fatal(err)
	}

	planID, results, err := oidfplan.RunPlan(ctx, harness.New(harnessURL()), oidcc.Plan(s), 90*time.Second, "", func(r oidfplan.ModuleResult) {
		t.Logf("%-8s %-26s %s", r.Result, r.Status, strings.TrimPrefix(r.Module, oidcc.ModulePrefix))
	})
	if err != nil {
		t.Fatalf("create the plan: %v", err)
	}
	for _, v := range oidfplan.Judge(results, expected) {
		if v.Kind != oidfplan.VerdictOK {
			t.Errorf("%s: %s %s", v.Kind, v.Module, v.Detail)
		}
	}
	t.Logf("%d modules, plan %s/plan-detail.html?plan=%s", len(results), harnessURL(), planID)
}
