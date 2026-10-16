package keycloak_test

// EdDSA (Ed25519) DPoP proofs against Keycloak. Keycloak computing the same
// cnf.jkt as our RFC 8037 thumbprint is what shows the OKP thumbprint is
// right, since both of our sides use the one function.
//
// Keycloak accepts the "EdDSA" alg name and refuses RFC 9864's newer
// "Ed25519", which is why the SDK signs as EdDSA.
//
// See: https://www.rfc-editor.org/rfc/rfc8037#section-2
// See: https://github.com/panyam/oneauth/issues/395

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
)

func TestKeycloakDPoP_Ed25519KeyAgreesOnTheThumbprint(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key, err := client.NewEd25519DPoPKey()
	require.NoError(t, err)
	c := client.NewAuthClient(keycloakURL(), nil,
		client.WithASMetadata(&client.ASMetadata{TokenEndpoint: keycloakTokenEndpoint()}),
		client.WithDPoPKey(key))

	cred, err := c.Login(context.Background(), &client.LoginRequest{
		Username: testUsername, Password: testPassword, ClientID: dpopClientID, Scope: "openid",
	})
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), jktOf(t, cred.AccessToken), "Keycloak's cnf.jkt is our RFC 8037 thumbprint")

	// And oneauth's resource server accepts that Keycloak token under the
	// Ed25519 key.
	server, _ := newKeycloakBackedResource(t)
	proof, err := key.Proof(http.MethodGet, server.URL+"/resource", cred.AccessToken)
	require.NoError(t, err)
	resp := callResource(t, server, "DPoP", cred.AccessToken, proof)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
