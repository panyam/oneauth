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

// TestOIDF_OIDCC_FormPostBasicOP is the ratchet for issue 500. It runs
// every module of oidcc-formpost-basic-certification-test-plan, the Basic
// OP modules with response_mode=form_post, against a cmd/oneauth-server
// started with oneauth-oidcc.yaml, and fails on each module oidfplan.Judge
// finds out of line with known-gaps.yaml.
//
// It needs a fresh server on :8893 (`./scripts/exercise-oidf.sh oidccfp
// --go-test` starts one, as `make testoidf` does), and skips when either
// the harness or that server isn't reachable.
//
// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
// See: https://openid.net/certification/
func TestOIDF_OIDCC_FormPostBasicOP(t *testing.T) {
	serverURL := envOr("OIDF_OIDCC_FORMPOST_SERVER_URL", "https://localhost:8893")
	skipIfHarnessOrServerNotReady(t, serverURL, "OIDC Form Post Basic OP", "./scripts/exercise-oidf.sh oidccfp --go-test")

	expected, err := oidfplan.LoadExpectations(filepath.Join(findWorkspaceRoot(t), "tests", "conformance", "known-gaps.yaml"), oidcc.FormPostPlanName)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: probeTransport(t)}
	s := oidcc.Setup{
		Alias: "oneauth-oidccfp", HarnessURL: harnessURL(), IssuerURL: envOr("OIDF_OIDCC_FORMPOST_ISSUER", "https://host.docker.internal:8893"), Scope: oidcc.Scope,
		User: oidcc.ExerciseUser(),
	}
	ctx := context.Background()
	if err := oidcc.Prepare(ctx, hc, serverURL, &s); err != nil {
		t.Fatal(err)
	}

	planID, results, err := oidfplan.RunPlan(ctx, harness.New(harnessURL()), oidcc.FormPostPlan(s), 90*time.Second, "", func(r oidfplan.ModuleResult) {
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
