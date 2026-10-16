package e2e_test

// The SDK's automatic refresh against oneauth's standard token endpoint, for
// a confidential client: since issue 395 the refresh grant needs the
// client's credentials, which WithClientSecret supplies without storing them.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
// See: https://github.com/panyam/oneauth/issues/395

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
)

func TestSDKAutoRefresh_ConfidentialClient(t *testing.T) {
	env := newFullStackEnv(t, fullStackOpts{})
	reg := env.register(t, client.ClientRegistrationRequest{
		RedirectURIs:            []string{"http://localhost:1/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	store := &memCredentialStore{creds: map[string]*client.ServerCredential{}}
	c := client.NewAuthClient(env.server.URL, store,
		client.WithASMetadata(&client.ASMetadata{TokenEndpoint: env.tokenURL}),
		client.WithClientSecret(reg.ClientSecret))

	cred, err := c.LoginWithBrowser(context.Background(), &client.BrowserLoginRequest{
		AuthorizationEndpoint: env.server.URL + "/authorize",
		TokenEndpoint:         env.tokenURL,
		ClientID:              reg.ClientID,
		ClientSecret:          reg.ClientSecret,
		Timeout:               5 * time.Second,
		OpenBrowser:           client.FollowRedirects(nil),
	})
	require.NoError(t, err)

	cred.ExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, store.SetCredential(env.server.URL, cred))

	token, err := c.GetToken()
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.NotEqual(t, cred.AccessToken, token)

	stored, err := store.GetCredential(env.server.URL)
	require.NoError(t, err)
	assert.NotEqual(t, cred.RefreshToken, stored.RefreshToken, "the AS rotated the refresh token")
	assert.Equal(t, reg.ClientID, stored.ClientID)

	resp, err := c.HTTPClient().Get(env.server.URL + "/protected")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the refreshed token works at the resource")
}
