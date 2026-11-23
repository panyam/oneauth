package oauch

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSite_UsesOAuchFieldNames pins the JSON keys OAuch's importer
// reads. A renamed key would import as OAuch's default and quietly change
// the run.
func TestNewSite_UsesOAuchFieldNames(t *testing.T) {
	d := Discovery{
		Issuer:                "https://as.example",
		AuthorizationEndpoint: "https://as.example/authorize",
		TokenEndpoint:         "https://as.example/api/token",
		RevocationEndpoint:    "https://as.example/oauth/revoke",
		JWKSURI:               "https://as.example/.well-known/jwks.json",
		UserinfoEndpoint:      "https://as.example/userinfo",
	}
	site := NewSite("s", d, "https://oauch.example/Callback",
		Client{ClientId: "a", ClientSecret: "as", Scope: Scope}, Client{ClientId: "b", ClientSecret: "bs", Scope: Scope})
	raw, err := json.Marshal([]Site{site})
	require.NoError(t, err)

	var got []struct {
		Name                 string
		CurrentConfiguration map[string]any
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "s", got[0].Name)
	cfg := got[0].CurrentConfiguration
	assert.Equal(t, "https://as.example/authorize", cfg["AuthorizationUri"])
	assert.Equal(t, "https://as.example/api/token", cfg["TokenUri"])
	assert.Equal(t, "https://as.example/oauth/revoke", cfg["RevocationUri"])
	assert.Equal(t, "https://as.example/.well-known/jwks.json", cfg["JwksUri"])
	assert.Equal(t, "https://as.example/userinfo", cfg["TestUri"])
	assert.Equal(t, "https://as.example", cfg["OpenIdIssuer"])
	assert.Equal(t, "https://oauch.example/Callback", cfg["CallbackUri"])
	assert.Equal(t, map[string]any{"ClientId": "a", "ClientSecret": "as", "Scope": Scope}, cfg["DefaultClient"])
	assert.Equal(t, map[string]any{"ClientId": "b", "ClientSecret": "bs", "Scope": Scope}, cfg["AlternativeClient"])
	assert.Len(t, cfg["SelectedStandards"], len(Standards))
	assert.EqualValues(t, 2, cfg["PKCEDefault"])
	assert.EqualValues(t, 100, cfg["ResponseMode"])
}

// dashboardFixture is the sidebar markup of OAuch's dashboard at the
// pinned commit.
const dashboardFixture = `<li class="nav-header">All available sites (2)</li>
    <li class="nav-item">
            <a href="/Dashboard/Results/82349687-b90a-4471-9f01-bfe598c69886" class="nav-link">
                <i class="nav-icon fas fa-circle" style="font-size: 0.3rem;"></i>
                <p>oneauth-1</p>
            </a>
    </li>
    <li class="nav-item">
            <a href="/Dashboard/Results/0f2c4a8e-1111-4222-8333-944455556666" class="nav-link">
                <i class="nav-icon fas fa-circle" style="font-size: 0.3rem;"></i>
                <p>oneauth-2</p>
            </a>
    </li>`

func TestSiteID_FindsTheSiteByName(t *testing.T) {
	id, ok := siteID(dashboardFixture, "oneauth-2")
	assert.True(t, ok)
	assert.Equal(t, "0f2c4a8e-1111-4222-8333-944455556666", id)
	_, ok = siteID(dashboardFixture, "other")
	assert.False(t, ok)
}
