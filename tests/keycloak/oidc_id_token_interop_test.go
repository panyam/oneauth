package keycloak_test

// Keycloak as the reference OpenID Provider for the SDK's ID token checks:
// LoginWithBrowser with VerifyIDToken must accept Keycloak's real ID token,
// and that token must carry the claim names oneauth's does.
// cmd/oneauth-server/oidc_sdk_test.go runs the same login against the
// reference server.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// See: https://github.com/panyam/oneauth/issues/453

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
)

// sharedIDTokenClaims are the claims both oneauth and Keycloak put in a
// code-flow ID token, `typ: ID` marker included. Keep in step with
// cmd/oneauth-server/oidc_sdk_test.go.
var sharedIDTokenClaims = []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "typ"}

func TestKeycloakOIDC_SDKVerifiesTheIDToken(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err)

	req, _ := headlessLoginRequest(t, confidentialClientID, keycloakPasswordLogin(t, testUsername, testPassword))
	req.ClientSecret = confidentialClientSecret
	req.VerifyIDToken = true

	cred, err := client.NewAuthClient(keycloakURL(), nil, client.WithASMetadata(meta)).LoginWithBrowser(context.Background(), req)
	require.NoError(t, err)

	got := cred.IDTokenClaims
	require.NotNil(t, got)
	assert.Equal(t, meta.Issuer, got.Issuer)
	assert.Contains(t, got.Audience, confidentialClientID)
	assert.NotEmpty(t, got.Subject, "the realm's basic scope supplies sub")
	assert.Equal(t, got.Subject, cred.UserID)
	for _, name := range sharedIDTokenClaims {
		assert.Contains(t, got.Claims, name)
	}
	assert.Equal(t, "ID", got.Claims["typ"])
}
