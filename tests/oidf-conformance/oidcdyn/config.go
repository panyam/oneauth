// Package oidcdyn defines the two OpenID Foundation OP plans in which the
// harness registers its own clients through oneauth's RFC 7591 endpoint:
// the Dynamic OP certification plan (oidcc-dynamic-certification-test-plan,
// issue 493) and the catch-all oidcc-test-plan, run once per client
// authentication method oneauth advertises (issue 494). oidfplan runs them.
//
// Both plans log the user in exactly as the Basic OP plan does, so the
// browser automation comes from package oidcc.
package oidcdyn

import (
	"fmt"
	"slices"
	"strings"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidcc"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
)

// DynamicPlanName is the Dynamic OP certification plan.
const DynamicPlanName = "oidcc-dynamic-certification-test-plan"

// TestPlanName is the catch-all OP plan. oneauth runs it for the code flow
// with each client authentication method in TestPlanAuthTypes.
const TestPlanName = "oidcc-test-plan"

// TestPlanAuthTypes are the client authentication methods oidcc-test-plan
// runs with. oneauth's discovery advertises these and client_secret_basic,
// which the Basic and Dynamic plans already cover. Two variants are left
// out. mtls needs certificate-bound clients, which oneauth doesn't have
// (issue 335). none is a public client, and the plan sends it without
// PKCE, which oneauth requires of public clients (RFC 9700 §2.1.1), so
// every flow stops at the authorization endpoint.
var TestPlanAuthTypes = []string{"client_secret_post", "client_secret_jwt", "private_key_jwt"}

// Setup is everything a plan config needs. The harness registers its own
// clients, so only the user is prepared up front.
type Setup struct {
	// Alias names the plan in the harness and forms its redirect URI.
	Alias string
	// HarnessURL is the harness origin the redirect URI points at.
	HarnessURL string
	// IssuerURL is oneauth's public URL as the harness container reaches
	// it, which is also the token issuer.
	IssuerURL string
	User      oidfplan.User
}

// DynamicPlan is the Dynamic OP certification plan for the code flow.
func DynamicPlan(s Setup) oidfplan.Plan {
	return oidfplan.Plan{
		Name:    DynamicPlanName,
		Variant: map[string]string{"response_type": "code"},
		Config:  planConfig(s, "oneauth OIDC Dynamic OP (issue 493)"),
	}
}

// DynamicImplicitResponseTypes are the implicit response types the
// Dynamic plan runs with besides code (issue 507). oneauth serves them
// with code_flow.implicit, to clients registered for them; hybrid types
// aren't supported.
var DynamicImplicitResponseTypes = []string{"id_token", "id_token token"}

// DynamicImplicitPlan is the Dynamic OP plan for one implicit response
// type. Its Key carries the type, so each run has its own known-gaps.yaml
// entries and run record.
func DynamicImplicitPlan(s Setup, responseType string) (oidfplan.Plan, error) {
	if !slices.Contains(DynamicImplicitResponseTypes, responseType) {
		return oidfplan.Plan{}, fmt.Errorf("response type %q: want one of %v", responseType, DynamicImplicitResponseTypes)
	}
	return oidfplan.Plan{
		Name:    DynamicPlanName,
		Key:     DynamicImplicitPlanKey(responseType),
		Variant: map[string]string{"response_type": responseType},
		Config:  planConfig(s, "oneauth OIDC Dynamic OP, "+responseType+" (issue 507)"),
	}, nil
}

// DynamicImplicitPlanKey is the known-gaps.yaml plan name for one implicit
// Dynamic run: the plan name with the response type, spaces as
// underscores.
func DynamicImplicitPlanKey(responseType string) string {
	return DynamicPlanName + "-" + strings.ReplaceAll(responseType, " ", "_")
}

// TestPlan is oidcc-test-plan for the code flow with dynamically registered
// clients using authType. Its Key carries authType, so each run has its own
// known-gaps.yaml entries and its own run record.
func TestPlan(s Setup, authType string) (oidfplan.Plan, error) {
	if !slices.Contains(TestPlanAuthTypes, authType) {
		return oidfplan.Plan{}, fmt.Errorf("client auth type %q: want one of %v", authType, TestPlanAuthTypes)
	}
	return oidfplan.Plan{
		Name: TestPlanName,
		Key:  TestPlanKey(authType),
		Variant: map[string]string{
			"client_registration": "dynamic_client",
			"response_type":       "code",
			"client_auth_type":    authType,
			"response_mode":       "default",
		},
		Config: planConfig(s, "oneauth oidcc-test-plan, "+authType+" (issue 494)"),
	}, nil
}

// TestPlanKey is the known-gaps.yaml plan name for one oidcc-test-plan run.
func TestPlanKey(authType string) string { return TestPlanName + "-" + authType }

// ModuleBrowsers is the Basic plan's per-module browser automation
// (oidcc.ModuleBrowsers) plus the modules only these plans have:
//
//   - redirect-uri-query-mismatch, redirect-uri-query-added and
//     ensure-redirect-uri-in-authorization-request send a redirect URI
//     the client didn't register, or none. oneauth shows its error page
//     and never redirects, so the browser captures that page, as for the
//     Basic plan's ensure-registered-redirect-uri.
//   - registration-logo-uri, -policy-uri and -tos-uri register a client
//     with that URI and ask for a screenshot of the consent page, where a
//     person checks the URI is shown. The browser captures the page and
//     stops there: the screenshot finishes the module, and approving as
//     well makes the harness throw.
func ModuleBrowsers(s Setup) map[string][]oidfplan.BrowserTask {
	basic := oidcc.Setup{Alias: s.Alias, HarnessURL: s.HarnessURL, IssuerURL: s.IssuerURL, User: s.User}
	out := oidcc.ModuleBrowsers(basic)
	errorPage := out[oidcc.PlanModule("ensure-registered-redirect-uri")]
	for _, m := range []string{"redirect-uri-query-mismatch", "redirect-uri-query-added", "ensure-redirect-uri-in-authorization-request"} {
		out[oidcc.PlanModule(m)] = errorPage
	}
	consent := []oidfplan.BrowserTask{{Match: s.IssuerURL + "/authorize*", Tasks: []oidfplan.BrowserStep{
		oidfplan.LoginStep(s.IssuerURL, s.User),
		{Task: "Consent page", Match: s.IssuerURL + "/authorize*", Commands: [][]any{
			{"wait", "xpath", "//h1[starts-with(text(),'Authorize ')]", 10, "Authorize", "update-image-placeholder"},
		}},
	}}}
	for _, m := range []string{"registration-logo-uri", "registration-policy-uri", "registration-tos-uri"} {
		out[oidcc.PlanModule(m)] = consent
	}
	return out
}

func planConfig(s Setup, description string) map[string]any {
	basic := oidcc.Setup{Alias: s.Alias, HarnessURL: s.HarnessURL, IssuerURL: s.IssuerURL, User: s.User}
	overrides := map[string]any{}
	for module, browser := range ModuleBrowsers(s) {
		overrides[module] = map[string]any{"browser": browser}
	}
	return map[string]any{
		"alias":       s.Alias,
		"description": description,
		"server":      map[string]any{"discoveryUrl": s.IssuerURL + "/.well-known/openid-configuration"},
		"browser":     oidcc.BrowserAutomation(basic),
		"override":    overrides,
	}
}

// ExerciseUser is the user both plans log in as, with the standard profile
// claims so the scope modules find them.
func ExerciseUser() oidfplan.User {
	return oidfplan.User{Email: "oidcdyn-user@example.com", Password: "oidcdyn-exercise-password", Profile: oidfplan.StandardProfile()}
}
