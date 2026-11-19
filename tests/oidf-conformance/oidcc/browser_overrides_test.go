package oidcc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every override is in the plan config under the module's full name.
func TestPlanConfig_CarriesTheModuleOverrides(t *testing.T) {
	raw, err := json.Marshal(PlanConfig(testSetup()))
	require.NoError(t, err)
	var got struct {
		Override map[string]struct {
			Browser []json.RawMessage `json:"browser"`
		} `json:"override"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	for _, m := range []string{"oidcc-response-type-missing", "oidcc-ensure-registered-redirect-uri", "oidcc-prompt-login", "oidcc-max-age-1"} {
		assert.NotEmpty(t, got.Override[m].Browser, m)
	}
}

// The re-login modules complete one normal flow, then expect the login
// page again on the second visit and capture it for the screenshot.
func TestModuleBrowsers_ReloginCapturesTheSecondLoginPage(t *testing.T) {
	b := ModuleBrowsers(testSetup())[PlanModule("prompt-login")]
	require.Len(t, b, 2)
	assert.Equal(t, 1, b[0].MatchLimit, "the first visit runs the normal flow once")
	first := b[1].Tasks[0]
	assert.Equal(t, "Login page", first.Task)
	assert.False(t, first.Optional, "a skipped login must fail the module rather than pass it")
	assert.Equal(t, "update-image-placeholder", first.Commands[0][5])
}

// The selectors the overrides wait for exist in oneauth's pages, so a
// template change shows up here rather than as a harness timeout.
func TestModuleBrowsers_SelectorsExistInTheServerPages(t *testing.T) {
	login, err := os.ReadFile(filepath.Join("..", "..", "..", "cmd", "oneauth-server", "templates", "login.html"))
	require.NoError(t, err)
	authorize, err := os.ReadFile(filepath.Join("..", "..", "..", "apiauth", "authorize_verification_handler.go"))
	require.NoError(t, err)
	assert.Contains(t, string(login), `<h1 class="text-2xl font-bold mb-2">Login</h1>`)
	assert.Contains(t, string(login), `name="username"`)
	assert.Contains(t, string(authorize), `id="authorize-error"`)
}
