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

// TestOIDF_OIDCC_ImplicitOP is a ratchet for issue 526. It runs every
// module of oidcc-implicit-certification-test-plan against a
// cmd/oneauth-server started with oneauth-oidcc.yaml, which turns on the
// opt-in implicit flow (issue 507). It fails on each module oidfplan.Judge
// finds out of line with known-gaps.yaml.
//
// It needs a fresh server on :8894 (`./scripts/exercise-oidf.sh oidcci
// --go-test` starts one, as `make testoidf` does), and skips when either
// the harness or that server isn't reachable.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
// See: https://openid.net/certification/
func TestOIDF_OIDCC_ImplicitOP(t *testing.T) {
	serverURL := envOr("OIDF_OIDCCI_SERVER_URL", "https://localhost:8894")
	skipIfHarnessOrServerNotReady(t, serverURL, "OIDC Implicit OP", "./scripts/exercise-oidf.sh oidcci --go-test")
	runImplicitPlan(t, serverURL, envOr("OIDF_OIDCCI_ISSUER", "https://host.docker.internal:8894"), "oneauth-oidcci", oidcc.ImplicitPlan)
}

// TestOIDF_OIDCC_FormPostImplicitOP is the other ratchet for issue 526:
// oidcc-formpost-implicit-certification-test-plan, the Implicit OP modules
// with response_mode=form_post, against a fresh server on :8896
// (`./scripts/exercise-oidf.sh oidccfpi --go-test`).
//
// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
// See: https://openid.net/certification/
func TestOIDF_OIDCC_FormPostImplicitOP(t *testing.T) {
	serverURL := envOr("OIDF_OIDCCFPI_SERVER_URL", "https://localhost:8896")
	skipIfHarnessOrServerNotReady(t, serverURL, "OIDC Form Post Implicit OP", "./scripts/exercise-oidf.sh oidccfpi --go-test")
	runImplicitPlan(t, serverURL, envOr("OIDF_OIDCCFPI_ISSUER", "https://host.docker.internal:8896"), "oneauth-oidccfpi", oidcc.FormPostImplicitPlan)
}

func runImplicitPlan(t *testing.T, serverURL, issuer, alias string, plan func(oidcc.Setup) oidfplan.Plan) {
	t.Helper()
	hc := &http.Client{Timeout: 30 * time.Second, Transport: probeTransport(t)}
	s := oidcc.Setup{Alias: alias, HarnessURL: harnessURL(), IssuerURL: issuer, Scope: oidcc.Scope, User: oidcc.ExerciseUser()}
	ctx := context.Background()
	if err := oidcc.PrepareImplicit(ctx, hc, serverURL, &s); err != nil {
		t.Fatal(err)
	}
	p := plan(s)
	expected, err := oidfplan.LoadExpectations(filepath.Join(findWorkspaceRoot(t), "tests", "conformance", "known-gaps.yaml"), p.ManifestKey())
	if err != nil {
		t.Fatal(err)
	}

	planID, results, err := oidfplan.RunPlan(ctx, harness.New(harnessURL()), p, 90*time.Second, "", func(r oidfplan.ModuleResult) {
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
