package keycloak_test

// The SDK's automatic refresh against Keycloak. Before issue 395 it always
// posted to oneauth's own /auth/cli/token, which Keycloak doesn't serve, so a
// client logged in to Keycloak could never refresh in the background.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
// See: https://github.com/panyam/oneauth/issues/395

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
)

func TestKeycloak_SDKAutoRefresh(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		clientID, secret string
		key              bool
	}{
		"confidential client": {confidentialClientID, confidentialClientSecret, false},
		"DPoP public client":  {dpopClientID, "", true},
	} {
		t.Run(name, func(t *testing.T) {
			store := &kclCredentialStore{creds: make(map[string]*client.ServerCredential)}
			opts := []client.ClientOption{client.WithASMetadata(meta)}
			if tc.secret != "" {
				opts = append(opts, client.WithClientSecret(tc.secret))
			}
			if tc.key {
				key, err := client.NewDPoPKey()
				require.NoError(t, err)
				opts = append(opts, client.WithDPoPKey(key))
			}
			c := client.NewAuthClient(keycloakURL(), store, opts...)

			cred, err := c.Login(context.Background(), &client.LoginRequest{
				Username: testUsername, Password: testPassword, ClientID: tc.clientID, ClientSecret: tc.secret, Scope: "openid",
			})
			require.NoError(t, err)
			require.NotEmpty(t, cred.RefreshToken)

			cred.ExpiresAt = time.Now().Add(-time.Minute)
			require.NoError(t, store.SetCredential(keycloakURL(), cred))

			token, err := c.GetToken()
			require.NoError(t, err)
			require.NotEmpty(t, token)
			assert.NotEqual(t, cred.AccessToken, token, "Keycloak issued a new access token")
		})
	}
}
