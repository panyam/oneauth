package oidfconformance_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/tests/oidf-conformance/harness"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidcc"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidcdyn"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
)

// TestOIDF_OIDCC_DynamicOP is the ratchet for issue 493. It runs every
// module of oidcc-dynamic-certification-test-plan, in which the harness
// registers its own clients through oneauth's RFC 7591 endpoint, against a
// cmd/oneauth-server on :8891, and fails on each module oidfplan.Judge
// finds out of line with known-gaps.yaml.
//
// `./scripts/exercise-oidf.sh oidcdyn --go-test` starts the server, as
// `make testoidf` does. The test skips when the harness or server isn't
// reachable.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html
// See: https://openid.net/certification/
func TestOIDF_OIDCC_DynamicOP(t *testing.T) {
	serverURL := envOr("OIDF_OIDCDYN_SERVER_URL", "https://localhost:8891")
	skipIfHarnessOrServerNotReady(t, serverURL, "OIDC Dynamic OP", "./scripts/exercise-oidf.sh oidcdyn --go-test")
	// OIDF_RESPONSE_TYPE runs an implicit variant instead of code (issue 507).
	if rt := os.Getenv("OIDF_RESPONSE_TYPE"); rt != "" {
		alias := "oneauth-oidcdyn-" + strings.ReplaceAll(rt, " ", "-")
		runDynamicRegistrationPlan(t, serverURL, "https://host.docker.internal:8891", alias, func(s oidcdyn.Setup) oidfplan.Plan {
			p, err := oidcdyn.DynamicImplicitPlan(s, rt)
			if err != nil {
				t.Fatal(err)
			}
			return p
		})
		return
	}
	runDynamicRegistrationPlan(t, serverURL, "https://host.docker.internal:8891", "oneauth-oidcdyn", oidcdyn.DynamicPlan)
}

// TestOIDF_OIDCC_TestPlan is the ratchet for issue 494: oidcc-test-plan for
// the code flow with OIDF_AUTH_TYPE's client auth method, against a
// cmd/oneauth-server on :8892. `AUTH=<method> ./scripts/exercise-oidf.sh
// oidcctp --go-test` starts the server and sets the method; `make testoidf`
// runs it once for each of oidcdyn.TestPlanAuthTypes.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
func TestOIDF_OIDCC_TestPlan(t *testing.T) {
	authType := os.Getenv("OIDF_AUTH_TYPE")
	if authType == "" {
		t.Skip("OIDF_AUTH_TYPE not set; run AUTH=<method> ./scripts/exercise-oidf.sh oidcctp --go-test")
	}
	serverURL := envOr("OIDF_OIDCCTP_SERVER_URL", "https://localhost:8892")
	skipIfHarnessOrServerNotReady(t, serverURL, "oidcc-test-plan", "AUTH="+authType+" ./scripts/exercise-oidf.sh oidcctp --go-test")
	alias := "oneauth-oidcctp-" + strings.ReplaceAll(authType, "_", "-")
	runDynamicRegistrationPlan(t, serverURL, "https://host.docker.internal:8892", alias, func(s oidcdyn.Setup) oidfplan.Plan {
		p, err := oidcdyn.TestPlan(s, authType)
		if err != nil {
			t.Fatal(err)
		}
		return p
	})
}

func runDynamicRegistrationPlan(t *testing.T, serverURL, issuer, alias string, plan func(oidcdyn.Setup) oidfplan.Plan) {
	t.Helper()
	hc := &http.Client{Timeout: 30 * time.Second, Transport: probeTransport(t)}
	s := oidcdyn.Setup{Alias: alias, HarnessURL: harnessURL(), IssuerURL: issuer, User: oidcdyn.ExerciseUser()}
	ctx := context.Background()
	if err := oidfplan.SignUp(ctx, hc, serverURL, s.User); err != nil {
		t.Fatalf("sign up the browser user: %v", err)
	}
	p := plan(s)
	expected, err := oidfplan.LoadExpectations(filepath.Join(findWorkspaceRoot(t), "tests", "conformance", "known-gaps.yaml"), p.ManifestKey())
	if err != nil {
		t.Fatal(err)
	}
	p.Manual = oidfplan.ManualModules(expected)
	p.Actions = map[string]func(context.Context) error{
		"oidcc-server-rotate-keys": oidfplan.RotateServerKeys(hc, serverURL),
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
