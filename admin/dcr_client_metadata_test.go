package admin_test

// OIDC Registration §2 client metadata in DCR (issue 507): jwks_uri for
// private_key_jwt clients, and the logo, policy and terms URIs the consent
// page shows.
//
// References:
//   - RFC 7591 §2 (https://www.rfc-editor.org/rfc/rfc7591#section-2)
//   - OIDC Registration §2 (https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
//   - CWE-918 SSRF (https://cwe.mitre.org/data/definitions/918.html)
//   - See: https://github.com/panyam/oneauth/issues/507

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

const jwksURIClient = `{"client_name":"jwks-uri","redirect_uris":["https://app.example/cb"],
	"grant_types":["authorization_code"],"token_endpoint_auth_method":"private_key_jwt",
	"jwks_uri":"https://app.example/jwks.json","token_endpoint_auth_signing_alg":"ES256"}`

// A private_key_jwt client can register a jwks_uri instead of inline keys.
// It gets no KeyStore entry: its keys are fetched when it authenticates.
func TestDCR_JWKSURIClient(t *testing.T) {
	registrar, ks, code, resp := dcrPost(t, jwksURIClient)
	require.Equal(t, http.StatusCreated, code, resp)
	assert.Equal(t, "https://app.example/jwks.json", resp["jwks_uri"])
	assert.Equal(t, "ES256", resp["token_endpoint_auth_signing_alg"])
	assert.Nil(t, resp["client_secret"])

	id := resp["client_id"].(string)
	_, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: id})
	assert.Error(t, err, "a jwks_uri client has no stored key")
	got, err := registrar.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: id})
	require.NoError(t, err)
	assert.Equal(t, "https://app.example/jwks.json", got.App.JWKSURI)
	assert.Equal(t, "ES256", got.App.TokenEndpointAuthSigningAlg)
}

// See: https://www.rfc-editor.org/rfc/rfc7591#section-2 (jwks and jwks_uri MUST NOT both be present)
func TestDCR_JWKSURIRefusals(t *testing.T) {
	base := `"client_name":"x","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"private_key_jwt"`
	for name, extra := range map[string]string{
		"jwks and jwks_uri":     `"jwks_uri":"https://app.example/jwks.json","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`,
		"plain http":            `"jwks_uri":"http://app.example/jwks.json"`,
		"loopback literal":      `"jwks_uri":"https://127.0.0.1/jwks.json"`,
		"private literal":       `"jwks_uri":"https://10.0.0.5/jwks.json"`,
		"fragment":              `"jwks_uri":"https://app.example/jwks.json#k"`,
		"relative":              `"jwks_uri":"/jwks.json"`,
		"neither":               `"token_endpoint_auth_signing_alg":"ES256"`,
		"symmetric signing alg": `"jwks_uri":"https://app.example/jwks.json","token_endpoint_auth_signing_alg":"HS256"`,
		"unknown signing alg":   `"jwks_uri":"https://app.example/jwks.json","token_endpoint_auth_signing_alg":"XX999"`,
		"alg none":              `"jwks_uri":"https://app.example/jwks.json","token_endpoint_auth_signing_alg":"none"`,
	} {
		_, _, code, resp := dcrPost(t, "{"+base+","+extra+"}")
		assert.Equal(t, http.StatusBadRequest, code, name)
		assert.Equal(t, "invalid_client_metadata", resp["error"], name)
	}
}

// jwks_uri belongs to private_key_jwt; a secret-based client has no use for
// it, so it's refused rather than silently stored.
func TestDCR_JWKSURIOnlyForPrivateKeyJWT(t *testing.T) {
	_, _, code, resp := dcrPost(t, `{"client_name":"x","redirect_uris":["https://app.example/cb"],"jwks_uri":"https://app.example/jwks.json"}`)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_client_metadata", resp["error"])
}

// The display URIs are stored and echoed, and only absolute https URLs are
// accepted: the consent page puts them in an <img src> and two links.
func TestDCR_DisplayURIs(t *testing.T) {
	registrar, _, code, resp := dcrPost(t, `{"client_name":"x","redirect_uris":["https://app.example/cb"],
		"logo_uri":"https://app.example/logo.png","policy_uri":"https://app.example/privacy","tos_uri":"https://app.example/terms"}`)
	require.Equal(t, http.StatusCreated, code, resp)
	assert.Equal(t, "https://app.example/logo.png", resp["logo_uri"])
	assert.Equal(t, "https://app.example/privacy", resp["policy_uri"])
	assert.Equal(t, "https://app.example/terms", resp["tos_uri"])
	got, err := registrar.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: resp["client_id"].(string)})
	require.NoError(t, err)
	assert.Equal(t, "https://app.example/logo.png", got.App.LogoURI)
	assert.Equal(t, "https://app.example/privacy", got.App.PolicyURI)
	assert.Equal(t, "https://app.example/terms", got.App.TOSURI)

	for name, field := range map[string]string{
		"http logo":         `"logo_uri":"http://app.example/logo.png"`,
		"javascript policy": `"policy_uri":"javascript:alert(1)"`,
		"data logo":         `"logo_uri":"data:image/png;base64,AAAA"`,
		"relative tos":      `"tos_uri":"/terms"`,
	} {
		_, _, code, resp := dcrPost(t, `{"client_name":"x","redirect_uris":["https://app.example/cb"],`+field+`}`)
		assert.Equal(t, http.StatusBadRequest, code, name)
		assert.Equal(t, "invalid_client_metadata", resp["error"], name)
	}
}

// RFC 7592 update: display URIs change and are validated as on register, a
// jwks_uri client may move its jwks_uri, and an inline-key client can't
// switch to jwks_uri (that would re-key it).
func TestDCR_UpdateClientMetadata(t *testing.T) {
	registrar, _, code, resp := dcrPost(t, jwksURIClient)
	require.Equal(t, http.StatusCreated, code)
	id, tok := resp["client_id"].(string), resp["registration_access_token"].(string)
	update := func(md *admin.DCRRequest) error {
		md.RedirectURIs, md.GrantTypes = []string{"https://app.example/cb"}, []string{"authorization_code"}
		r, err := registrar.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{ClientID: id, AccessToken: tok, Metadata: md})
		if err == nil {
			tok = r.Registration.RegistrationAccessToken
		}
		return err
	}
	require.NoError(t, update(&admin.DCRRequest{JWKSURI: "https://app.example/v2/jwks.json", LogoURI: "https://app.example/new.png"}))
	got, err := registrar.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: id})
	require.NoError(t, err)
	assert.Equal(t, "https://app.example/v2/jwks.json", got.App.JWKSURI)
	assert.Equal(t, "https://app.example/new.png", got.App.LogoURI)
	assert.ErrorIs(t, update(&admin.DCRRequest{LogoURI: "http://app.example/new.png"}), admin.ErrInvalidClientMetadata)

	inline, _, code, resp := dcrPost(t, `{"client_name":"inline","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],
		"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}}`)
	require.Equal(t, http.StatusCreated, code, resp)
	_, err = inline.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{
		ClientID: resp["client_id"].(string), AccessToken: resp["registration_access_token"].(string),
		Metadata: &admin.DCRRequest{RedirectURIs: []string{"https://app.example/cb"}, GrantTypes: []string{"authorization_code"}, JWKSURI: "https://app.example/jwks.json"},
	})
	assert.ErrorIs(t, err, admin.ErrInvalidClientMetadata)
}
