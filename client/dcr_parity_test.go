package client

// The SDK's DCR structs carry every field oneauth's DCR endpoint reads
// and echoes (issue 557). A field the server adds without the SDK would
// be invisible to SDK callers, so the drift test fails the build first.

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
)

func jsonTags(t reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			out[name] = true
		}
	}
	return out
}

func TestDCRStructs_CoverTheServersFields(t *testing.T) {
	for _, pair := range []struct{ server, sdk reflect.Type }{
		{reflect.TypeOf(admin.DCRResponse{}), reflect.TypeOf(ClientRegistrationResponse{})},
		{reflect.TypeOf(admin.DCRRequest{}), reflect.TypeOf(ClientRegistrationRequest{})},
	} {
		sdk := jsonTags(pair.sdk)
		for name := range jsonTags(pair.server) {
			assert.True(t, sdk[name], "%s has %q but %s doesn't", pair.server.Name(), name, pair.sdk.Name())
		}
	}
}

// Every field the SDK sends comes back in the SDK's response struct, over
// the wire, from a real oneauth DCR endpoint.
func TestDCRStructs_RoundTripThroughOneauth(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	r := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	r.IssuerBaseURL = "http://example.com"
	r.UserinfoSigningAlgs = []string{"ES256"}
	r.AuthorizationSigningAlgs = []string{"ES256"}
	srv := httptest.NewServer(&admin.DCRHandler{KeyStore: ks, Auth: admin.NewNoAuth(), Registrar: r, IssuerBaseURL: "http://example.com"})
	t.Cleanup(srv.Close)

	resp, err := RegisterClient(srv.URL, ClientRegistrationRequest{
		ClientName:                       "parity",
		RedirectURIs:                     []string{"https://rp.example/cb"},
		GrantTypes:                       []string{"authorization_code"},
		ResponseTypes:                    []string{"code"},
		LogoURI:                          "https://rp.example/logo.png",
		PolicyURI:                        "https://rp.example/policy",
		TOSURI:                           "https://rp.example/tos",
		SubjectType:                      "public",
		UserinfoSignedResponseAlg:        "ES256",
		AuthorizationSignedResponseAlg:   "ES256",
		BackchannelLogoutURI:             "https://rp.example/bcl",
		BackchannelLogoutSessionRequired: true,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"code"}, resp.ResponseTypes)
	assert.Equal(t, "https://rp.example/logo.png", resp.LogoURI)
	assert.Equal(t, "https://rp.example/policy", resp.PolicyURI)
	assert.Equal(t, "https://rp.example/tos", resp.TOSURI)
	assert.Equal(t, "public", resp.SubjectType)
	assert.Equal(t, "ES256", resp.UserinfoSignedResponseAlg)
	assert.Equal(t, "ES256", resp.AuthorizationSignedResponseAlg)
	assert.Equal(t, "https://rp.example/bcl", resp.BackchannelLogoutURI)
	assert.True(t, resp.BackchannelLogoutSessionRequired)
}

// JWKS is passed through as raw JSON, so a caller hands over its JWK Set
// as it has it.
func TestDCRStructs_JWKSIsRawJSON(t *testing.T) {
	req := ClientRegistrationRequest{ClientName: "k", JWKS: json.RawMessage(`{"keys":[]}`)}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"jwks":{"keys":[]}`)
}
