package admin_test

// authorization_signed_response_alg in DCR (JARM §3, issue 413). It picks
// the algorithm the AS signs a client's JARM responses with, so the AS
// accepts only an algorithm it can sign with, and never `none`.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-3
// See: https://github.com/panyam/oneauth/issues/413

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
)

const jarmAlgClient = `{"client_name":"jarm","redirect_uris":["https://rp.example/cb"],"grant_types":["authorization_code"],"authorization_signed_response_alg":"%s"}`

func jarmAlgRegistrar(algs ...string) *admin.AppRegistrar {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())
	r.IssuerBaseURL = "http://example.com"
	r.AuthorizationSigningAlgs = algs
	return r
}

func TestDCR_AuthorizationSignedResponseAlgIsStoredAndEchoed(t *testing.T) {
	r := jarmAlgRegistrar("RS256", "PS256")
	code, resp := registerWith(t, r, sprintf(jarmAlgClient, "PS256"))
	require.Equal(t, http.StatusCreated, code, resp)
	assert.Equal(t, "PS256", resp["authorization_signed_response_alg"])
	assert.Equal(t, "PS256", storedApp(t, r, resp).AuthorizationSignedResponseAlg)

	clientID, token := resp["client_id"].(string), resp["registration_access_token"].(string)
	read, err := r.GetRegistration(context.Background(), &admin.GetRegistrationRequest{ClientID: clientID, AccessToken: token})
	require.NoError(t, err)
	assert.Equal(t, "PS256", read.Registration.AuthorizationSignedResponseAlg)
}

func TestDCR_AuthorizationSignedResponseAlgTheASCannotSignWithIsRefused(t *testing.T) {
	for _, alg := range []string{"ES256", "none"} {
		code, resp := registerWith(t, jarmAlgRegistrar("RS256", "PS256"), sprintf(jarmAlgClient, alg))
		assert.Equal(t, http.StatusBadRequest, code, alg)
		assert.Equal(t, "invalid_client_metadata", resp["error"], alg)
	}

	code, resp := registerWith(t, jarmAlgRegistrar(), sprintf(jarmAlgClient, "RS256"))
	assert.Equal(t, http.StatusBadRequest, code, "JARM off")
	assert.Equal(t, "invalid_client_metadata", resp["error"])
}

// RFC 7592 PUT replaces the metadata, the alg included, and checks it the
// same way.
func TestDCR_AuthorizationSignedResponseAlgUpdates(t *testing.T) {
	r := jarmAlgRegistrar("RS256", "PS256")
	code, resp := registerWith(t, r, sprintf(jarmAlgClient, "PS256"))
	require.Equal(t, http.StatusCreated, code, resp)
	clientID, token := resp["client_id"].(string), resp["registration_access_token"].(string)
	ctx := context.Background()
	md := &admin.DCRRequest{ClientID: clientID, ClientName: "jarm", RedirectURIs: []string{"https://rp.example/cb"},
		GrantTypes: []string{"authorization_code"}}

	md.AuthorizationSignedResponseAlg = "none"
	_, err := r.UpdateRegistration(ctx, &admin.UpdateRegistrationRequest{ClientID: clientID, AccessToken: token, Metadata: md})
	assert.ErrorIs(t, err, admin.ErrInvalidClientMetadata)

	md.AuthorizationSignedResponseAlg = "RS256"
	updated, err := r.UpdateRegistration(ctx, &admin.UpdateRegistrationRequest{ClientID: clientID, AccessToken: token, Metadata: md})
	require.NoError(t, err)
	assert.Equal(t, "RS256", updated.Registration.AuthorizationSignedResponseAlg)
	assert.Equal(t, "RS256", storedApp(t, r, map[string]any{"client_id": clientID}).AuthorizationSignedResponseAlg)
}
