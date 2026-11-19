package oidcdyn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidcc"
	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSetup() Setup {
	return Setup{
		Alias:      "oneauth-oidcdyn",
		HarnessURL: "https://localhost.emobix.co.uk:8443",
		IssuerURL:  "https://host.docker.internal:8891",
		User:       oidfplan.User{Email: "dyn@example.com", Password: "dyn-password-1"},
	}
}

// The harness registers its own clients, so the config names none and
// carries only discovery, the browser and the overrides.
func TestDynamicPlan_ConfigRegistersNoClients(t *testing.T) {
	p := DynamicPlan(testSetup())
	assert.Equal(t, DynamicPlanName, p.ManifestKey())
	assert.Equal(t, map[string]string{"response_type": "code"}, p.Variant)
	raw, err := json.Marshal(p.Config)
	require.NoError(t, err)
	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.NotContains(t, got, "client")
	assert.JSONEq(t, `{"discoveryUrl":"https://host.docker.internal:8891/.well-known/openid-configuration"}`, string(got["server"]))
	assert.Contains(t, got, "browser")
	assert.Contains(t, got, "override")
}

// Each auth method is its own run, with its own manifest key, alias-free
// variant and dynamically registered clients.
func TestTestPlan_OneRunPerAuthType(t *testing.T) {
	keys := map[string]bool{}
	for _, a := range TestPlanAuthTypes {
		p, err := TestPlan(testSetup(), a)
		require.NoError(t, err)
		assert.Equal(t, TestPlanName, p.Name)
		assert.Equal(t, a, p.Variant["client_auth_type"])
		assert.Equal(t, "dynamic_client", p.Variant["client_registration"])
		assert.Equal(t, "code", p.Variant["response_type"])
		keys[p.ManifestKey()] = true
	}
	assert.Len(t, keys, len(TestPlanAuthTypes), "each run needs its own known-gaps.yaml key")
	assert.NotContains(t, keys, TestPlanName)
}

// mtls, none and client_secret_basic aren't run (see TestPlanAuthTypes).
func TestTestPlan_RefusesAuthTypesItDoesNotRun(t *testing.T) {
	for _, a := range []string{"mtls", "none", "client_secret_basic", ""} {
		_, err := TestPlan(testSetup(), a)
		assert.Error(t, err, a)
	}
}

// The Basic plan's overrides carry over, and the Dynamic plan's redirect
// and registration-URI modules get their own.
func TestModuleBrowsers(t *testing.T) {
	b := ModuleBrowsers(testSetup())
	for _, m := range []string{"ensure-registered-redirect-uri", "prompt-login", "redirect-uri-query-mismatch", "redirect-uri-query-added", "ensure-redirect-uri-in-authorization-request"} {
		assert.Contains(t, b, oidcc.PlanModule(m))
	}
	assert.Equal(t, b[oidcc.PlanModule("ensure-registered-redirect-uri")], b[oidcc.PlanModule("redirect-uri-query-mismatch")])
	for _, m := range []string{"registration-logo-uri", "registration-policy-uri", "registration-tos-uri"} {
		tasks := b[oidcc.PlanModule(m)]
		require.Len(t, tasks, 1, m)
		steps := tasks[0].Tasks
		last := steps[len(steps)-1]
		assert.Equal(t, "update-image-placeholder", last.Commands[len(last.Commands)-1][5], "%s ends on the screenshot, without approving", m)
	}
}

// The consent capture waits for the consent page's heading, so a template
// change shows up here rather than as a harness timeout.
func TestModuleBrowsers_ConsentHeadingExists(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "apiauth", "authorize_verification_handler.go"))
	require.NoError(t, err)
	assert.Contains(t, string(src), `<h1>Authorize {{.ClientName}}</h1>`)
}
