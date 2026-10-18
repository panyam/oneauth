package fapi2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const modulePrefix = "fapi2-security-profile-final-"

// planOverrides round-trips PlanConfig through JSON, as the harness receives
// it, and returns its per-module overrides.
func planOverrides(t *testing.T) map[string]struct {
	Browser []BrowserTask `json:"browser"`
} {
	t.Helper()
	raw, err := json.Marshal(PlanConfig(testSetup(t)))
	require.NoError(t, err)
	var cfg struct {
		Override map[string]struct {
			Browser []BrowserTask `json:"browser"`
		} `json:"override"`
	}
	require.NoError(t, json.Unmarshal(raw, &cfg))
	return cfg.Override
}

// The harness copies override[module] over the plan config for that module,
// so each override has to carry a complete browser list under its exact
// module name.
func TestPlanConfig_OverridesTheModulesTheDefaultScriptCantDrive(t *testing.T) {
	overrides := planOverrides(t)
	assert.ElementsMatch(t, []string{
		modulePrefix + "user-rejects-authentication",
		modulePrefix + "ensure-unsigned-authorization-request-without-using-par-fails",
		modulePrefix + "par-attempt-reuse-request_uri",
		modulePrefix + "par-attempt-to-use-expired-request_uri",
		modulePrefix + "par-attempt-to-use-request_uri-for-different-client",
		modulePrefix + "par-ensure-reused-request-uri-prior-to-auth-completion-succeeds",
	}, keys(overrides))
	for module, o := range overrides {
		assert.NotEmpty(t, o.Browser, module)
	}
}

func TestModuleBrowsers_UserRejectsClicksDeny(t *testing.T) {
	browser := planOverrides(t)[modulePrefix+"user-rejects-authentication"].Browser
	require.Len(t, browser, 1)
	assert.Equal(t, []string{"Login", "Consent", "Verify Complete"}, taskNames(browser[0]))
	assert.Equal(t, "//button[@value='deny']", browser[0].Tasks[1].Commands[0][2])
}

// An error-page module ends when the browser fills its screenshot
// placeholder, which the wait does only with "update-image-placeholder" as
// its last argument. A callback step after it would run on the error page
// itself, whose URL carries the harness callback in redirect_uri, and time
// out.
func TestModuleBrowsers_ErrorPageFillsThePlaceholder(t *testing.T) {
	for _, m := range []string{
		"ensure-unsigned-authorization-request-without-using-par-fails",
		"par-attempt-to-use-expired-request_uri",
		"par-attempt-to-use-request_uri-for-different-client",
	} {
		browser := planOverrides(t)[modulePrefix+m].Browser
		require.Len(t, browser, 1, m)
		assertErrorPageScript(t, browser[0])
	}
}

// The reuse module redeems the request_uri once through the normal flow, then
// sends the browser back with it and expects the error page.
func TestModuleBrowsers_ReuseRequestURIApprovesThenExpectsTheErrorPage(t *testing.T) {
	browser := planOverrides(t)[modulePrefix+"par-attempt-reuse-request_uri"].Browser
	require.Len(t, browser, 2)
	assert.Equal(t, 1, browser[0].MatchLimit)
	assert.Equal(t, []string{"Login", "Consent", "Verify Complete"}, taskNames(browser[0]))
	assert.Equal(t, 0, browser[1].MatchLimit)
	assertErrorPageScript(t, browser[1])
}

func assertErrorPageScript(t *testing.T, b BrowserTask) {
	t.Helper()
	assert.Equal(t, []string{"Login", "Error page"}, taskNames(b))
	errorPage := b.Tasks[1]
	require.Len(t, errorPage.Commands, 1)
	assert.Equal(t, []any{"wait", "id", "authorize-error", float64(10), "Authorization error", "update-image-placeholder"}, errorPage.Commands[0])
}

// The module refuses a login on the first of its two visits to the same
// /authorize URL, so the first matching entry handles one visit with no
// tasks, and the second visit falls through to the normal login.
func TestModuleBrowsers_ReusedRequestURISkipsLoginOnTheFirstVisit(t *testing.T) {
	browser := planOverrides(t)[modulePrefix+"par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"].Browser
	require.Len(t, browser, 2)
	assert.Equal(t, browser[0].Match, browser[1].Match)
	assert.Equal(t, 1, browser[0].MatchLimit)
	assert.Empty(t, browser[0].Tasks)
	assert.NotNil(t, browser[0].Tasks, "the harness expects a tasks array, not null")
	assert.Equal(t, 0, browser[1].MatchLimit)
	assert.Equal(t, []string{"Login", "Consent", "Verify Complete"}, taskNames(browser[1]))
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func taskNames(b BrowserTask) []string {
	var out []string
	for _, s := range b.Tasks {
		out = append(out, s.Task)
	}
	return out
}
