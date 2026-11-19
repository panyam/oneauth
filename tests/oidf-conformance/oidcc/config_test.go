package oidcc

import (
	"encoding/json"
	"testing"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSetup() Setup {
	return Setup{
		Alias:      "oneauth-oidcc",
		HarnessURL: "https://localhost.emobix.co.uk:8443",
		IssuerURL:  "https://host.docker.internal:8890",
		Scope:      Scope,
		Clients:    [2]Client{{ID: "c1", Secret: "s1"}, {ID: "c2", Secret: "s2"}},
		PostClient: Client{ID: "c3", Secret: "s3"},
		User:       oidfplan.User{Email: "oidcc@example.com", Password: "oidcc-password-1"},
	}
}

// The plan reads oneauth's discovery document and uses the clients the
// exercise registers, rather than registering its own.
func TestPlanVariant(t *testing.T) {
	assert.Equal(t, map[string]string{
		"server_metadata":     "discovery",
		"client_registration": "static_client",
	}, PlanVariant())
}

// The harness authenticates as each client with its secret, so the config
// carries all three, under the names the plan's static_client variant asks
// for (client, client2, client_secret_post).
func TestPlanConfig_CarriesTheThreeClientsAndTheirSecrets(t *testing.T) {
	s := testSetup()
	raw, err := json.Marshal(PlanConfig(s))
	require.NoError(t, err)
	type client struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Scope        string
	}
	var got struct {
		Alias  string
		Server struct {
			DiscoveryURL string `json:"discoveryUrl"`
		}
		Client           client
		Client2          client
		ClientSecretPost client `json:"client_secret_post"`
		Browser          []oidfplan.BrowserTask
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "oneauth-oidcc", got.Alias)
	assert.Equal(t, "https://host.docker.internal:8890/.well-known/openid-configuration", got.Server.DiscoveryURL)
	for want, c := range map[Client]client{s.Clients[0]: got.Client, s.Clients[1]: got.Client2, s.PostClient: got.ClientSecretPost} {
		assert.Equal(t, want.ID, c.ClientID)
		assert.Equal(t, want.Secret, c.ClientSecret)
		assert.Equal(t, Scope, c.Scope)
	}
	require.Len(t, got.Browser, 1)
	assert.Equal(t, "https://host.docker.internal:8890/authorize*", got.Browser[0].Match)
}

// Each client registers for the code grant with the given auth method, at
// the harness callback for this plan's alias, and asks for every scope the
// plan's modules use.
func TestRegistrationRequest(t *testing.T) {
	s := testSetup()
	body := RegistrationRequest("client_secret_post", RedirectURI(s.HarnessURL, s.Alias), Scope)
	assert.Equal(t, []string{"https://localhost.emobix.co.uk:8443/test/a/oneauth-oidcc/callback"}, body["redirect_uris"])
	assert.Equal(t, "client_secret_post", body["token_endpoint_auth_method"])
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, body["grant_types"])
	assert.Equal(t, []string{"code"}, body["response_types"])
	assert.Equal(t, "openid profile email address phone offline_access", body["scope"])
}
