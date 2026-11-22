package keycloak_test

// JARM against Keycloak (issue 412): the test-jarm client's responses are
// signed with PS256 by a key Keycloak publishes for that algorithm alone,
// so the SDK's verifier gets checked against another implementation's
// signing.
//
// See: https://openid.net/specs/oauth-v2-jarm.html
// See: https://github.com/panyam/oneauth/issues/412

import (
	"context"
	"testing"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jarmClientID = "test-jarm"

func TestKeycloak_JARMLogin(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	for _, mode := range []string{"jwt", "query.jwt", "form_post.jwt"} {
		t.Run(mode, func(t *testing.T) {
			meta, err := client.DiscoverAS(realmURL())
			require.NoError(t, err)
			req, _ := headlessLoginRequest(t, jarmClientID, testutil.KeycloakPasswordLogin(nil, testUsername, testPassword))
			req.ResponseMode = mode
			cred, err := client.NewAuthClient(keycloakURL(), nil, client.WithASMetadata(meta)).LoginWithBrowser(context.Background(), req)
			require.NoError(t, err)
			assert.NotEmpty(t, cred.AccessToken)
		})
	}
}
