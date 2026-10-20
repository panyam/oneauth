package fapi2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSetup(t *testing.T) Setup {
	t.Helper()
	k1, err := NewClientKey()
	require.NoError(t, err)
	k2, err := NewClientKey()
	require.NoError(t, err)
	return Setup{
		Alias:      "oneauth-fapi2",
		HarnessURL: "https://localhost.emobix.co.uk:8443",
		IssuerURL:  "https://host.docker.internal:8889",
		Scope:      "read",
		Clients:    [2]RegisteredClient{{ID: "c1", Key: k1}, {ID: "c2", Key: k2}},
		User:       User{Email: "fapi@example.com", Password: "fapi-password-1"},
	}
}

// The plan runs the FAPI 2.0 Security Profile as oneauth implements it:
// private_key_jwt, DPoP, no ID tokens yet (#339), plain FAPI.
func TestPlanVariant(t *testing.T) {
	assert.Equal(t, map[string]string{
		"fapi_profile":               "plain_fapi",
		"client_auth_type":           "private_key_jwt",
		"sender_constrain":           "dpop",
		"openid":                     "openid_connect",
		"authorization_request_type": "simple",
		"grant_management":           "disabled",
	}, PlanVariant())
}

func TestPlanConfig_ClientsCarryTheirPrivateKeys(t *testing.T) {
	s := testSetup(t)
	cfg := PlanConfig(s)
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	var got struct {
		Alias  string
		Server struct {
			DiscoveryURL string `json:"discoveryUrl"`
		}
		Client, Client2 struct {
			ClientID       string `json:"client_id"`
			Scope          string
			DPoPSigningAlg string `json:"dpop_signing_alg"`
			JWKS           struct {
				Keys []map[string]string
			}
		}
		Resource struct {
			ResourceURL    string `json:"resourceUrl"`
			ResourceMethod string `json:"resourceMethod"`
		}
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "oneauth-fapi2", got.Alias)
	assert.Equal(t, "https://host.docker.internal:8889/.well-known/openid-configuration", got.Server.DiscoveryURL)
	assert.Equal(t, "https://host.docker.internal:8889/api/me", got.Resource.ResourceURL)
	assert.Equal(t, "GET", got.Resource.ResourceMethod)
	for i, c := range []struct {
		ClientID       string `json:"client_id"`
		Scope          string
		DPoPSigningAlg string `json:"dpop_signing_alg"`
		JWKS           struct{ Keys []map[string]string }
	}{got.Client, got.Client2} {
		assert.Equal(t, s.Clients[i].ID, c.ClientID)
		assert.Equal(t, "read", c.Scope)
		assert.Equal(t, "ES256", c.DPoPSigningAlg)
		require.Len(t, c.JWKS.Keys, 1)
		k := c.JWKS.Keys[0]
		assert.NotEmpty(t, k["d"], "the harness signs client assertions, so it needs the private key")
		assert.Equal(t, "ES256", k["alg"])
		assert.Equal(t, s.Clients[i].Key.KeyID, k["kid"])
	}
}

// The registration sends only the public half.
func TestRegistrationRequest_PublicKeyOnly(t *testing.T) {
	s := testSetup(t)
	body := RegistrationRequest(s.Clients[0].Key, RedirectURI(s.HarnessURL, s.Alias), s.Scope)
	assert.Equal(t, []string{"https://localhost.emobix.co.uk:8443/test/a/oneauth-fapi2/callback"}, body["redirect_uris"])
	assert.Equal(t, "private_key_jwt", body["token_endpoint_auth_method"])
	assert.Equal(t, true, body["dpop_bound_access_tokens"])
	keys := body["jwks"].(map[string]any)["keys"].([]map[string]string)
	require.Len(t, keys, 1)
	assert.NotContains(t, keys[0], "d")
}

func TestClientRedirectURI_SecondClientCarriesTheQuerySuffix(t *testing.T) {
	s := testSetup(t)
	base := "https://localhost.emobix.co.uk:8443/test/a/oneauth-fapi2/callback"
	assert.Equal(t, base, ClientRedirectURI(s.HarnessURL, s.Alias, 0))
	assert.Equal(t, base+"?dummy1=lorem&dummy2=ipsum", ClientRedirectURI(s.HarnessURL, s.Alias, 1))
}

// The browser automation fills in oneauth's own login, consent and error
// pages, so its selectors have to exist in those pages. A template edit that
// renames a field would otherwise only show up as a harness timeout.
func TestBrowserAutomation_SelectorsExistInTheServerPages(t *testing.T) {
	login, err := os.ReadFile(filepath.Join("..", "..", "..", "cmd", "oneauth-server", "templates", "login.html"))
	require.NoError(t, err)
	authorize, err := os.ReadFile(filepath.Join("..", "..", "..", "apiauth", "authorize_verification_handler.go"))
	require.NoError(t, err)

	s := testSetup(t)
	tasks := BrowserAutomation(s)
	require.Len(t, tasks, 1)
	assert.Equal(t, "https://host.docker.internal:8889/authorize*", tasks[0].Match)
	for _, browser := range ModuleBrowsers(s) {
		tasks = append(tasks, browser...)
	}
	pages := map[string]string{"Login": string(login), "Consent": string(authorize), "Error page": string(authorize)}
	for _, entry := range tasks {
		for _, task := range entry.Tasks {
			page, ok := pages[task.Task]
			if !ok {
				continue
			}
			for _, cmd := range task.Commands {
				locator, _ := cmd[2].(string)
				switch cmd[1] {
				case "name":
					assert.Contains(t, page, `name="`+locator+`"`, "%s: %v", task.Task, cmd)
				case "id":
					assert.Contains(t, page, `id="`+locator+`"`, "%s: %v", task.Task, cmd)
				case "xpath":
					// //button[@value='approve'] → value="approve"
					attr := strings.TrimSuffix(strings.SplitN(locator, "@", 2)[1], "']")
					assert.Contains(t, page, strings.Replace(attr, "='", `="`, 1)+`"`, "%s: %v", task.Task, cmd)
				}
			}
		}
	}
}
