package admin_test

// response_types in DCR (RFC 7591 §2, OIDC Registration §2, issue 507).
// "code" is the default and always allowed. The implicit types need a
// registrar that allows implicit, and the implicit grant to match.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2.1
// See: https://github.com/panyam/oneauth/issues/507

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

func implicitRegistrar(allow bool) *admin.AppRegistrar {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())
	r.IssuerBaseURL = "http://example.com"
	r.AllowImplicit = allow
	return r
}

func TestDCR_ResponseTypesDefaultToCode(t *testing.T) {
	r := implicitRegistrar(false)
	code, resp := registerWith(t, r, `{"redirect_uris":["https://app.example/cb"]}`)
	require.Equal(t, http.StatusCreated, code, resp)
	assert.Equal(t, []any{"code"}, resp["response_types"])
	got, err := r.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: resp["client_id"].(string)})
	require.NoError(t, err)
	assert.Equal(t, []string{"code"}, got.App.ResponseTypes)
}

func TestDCR_ImplicitResponseTypes(t *testing.T) {
	r := implicitRegistrar(true)
	code, resp := registerWith(t, r, `{"redirect_uris":["https://app.example/cb"],"response_types":["id_token","id_token token"],"grant_types":["implicit"]}`)
	require.Equal(t, http.StatusCreated, code, resp)
	assert.Equal(t, []any{"id_token", "id_token token"}, resp["response_types"])
	assert.Equal(t, []any{"implicit"}, resp["grant_types"])
}

// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
func TestDCR_ResponseTypeRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		allow bool
		body  string
	}{
		"implicit off":                  {false, `{"redirect_uris":["https://app.example/cb"],"response_types":["id_token"],"grant_types":["implicit"]}`},
		"implicit off, grant only":      {false, `{"redirect_uris":["https://app.example/cb"],"grant_types":["implicit"]}`},
		"unknown response_type":         {true, `{"redirect_uris":["https://app.example/cb"],"response_types":["token"]}`},
		"hybrid":                        {true, `{"redirect_uris":["https://app.example/cb"],"response_types":["code id_token"],"grant_types":["authorization_code","implicit"]}`},
		"implicit type without grant":   {true, `{"redirect_uris":["https://app.example/cb"],"response_types":["id_token"],"grant_types":["authorization_code"]}`},
		"code type without its grant":   {true, `{"redirect_uris":["https://app.example/cb"],"response_types":["code"],"grant_types":["implicit"]}`},
		"implicit with no redirect URI": {true, `{"response_types":["id_token"],"grant_types":["implicit"]}`},
	} {
		code, resp := registerWith(t, implicitRegistrar(tc.allow), tc.body)
		assert.Equal(t, http.StatusBadRequest, code, name)
		assert.Contains(t, []any{"invalid_client_metadata", "invalid_redirect_uri"}, resp["error"], name)
	}
}

// An update may change response_types under the same rules.
func TestDCR_UpdateResponseTypes(t *testing.T) {
	r := implicitRegistrar(true)
	code, resp := registerWith(t, r, `{"redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"]}`)
	require.Equal(t, http.StatusCreated, code)
	id, tok := resp["client_id"].(string), resp["registration_access_token"].(string)
	out, err := r.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{ClientID: id, AccessToken: tok, Metadata: &admin.DCRRequest{
		RedirectURIs: []string{"https://app.example/cb"}, GrantTypes: []string{"authorization_code", "implicit"}, ResponseTypes: []string{"code", "id_token token"},
	}})
	require.NoError(t, err)
	assert.Equal(t, []string{"code", "id_token token"}, out.Registration.ResponseTypes)
	_, err = r.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{ClientID: id, AccessToken: out.Registration.RegistrationAccessToken, Metadata: &admin.DCRRequest{
		RedirectURIs: []string{"https://app.example/cb"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"id_token"},
	}})
	assert.ErrorIs(t, err, admin.ErrInvalidClientMetadata)
}
