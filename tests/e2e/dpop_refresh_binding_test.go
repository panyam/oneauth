package e2e_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A confidential client's refresh token is constrained by the client's own
// authentication, so it carries no DPoP binding: the client can refresh with
// a new key, and the access token binds to that key. A public client's
// refresh token stays bound to the key it was issued to.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5
func TestFullStack_RefreshBindingFollowsClientType(t *testing.T) {
	for _, tc := range []struct {
		name       string
		authMethod string
		wantStatus int
	}{
		{"confidential client refreshes with a new key", "client_secret_basic", http.StatusOK},
		{"public client refresh stays bound", "none", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newFullStackEnv(t, fullStackOpts{})
			reg := env.register(t, client.ClientRegistrationRequest{
				RedirectURIs:            []string{"http://localhost:1/callback"},
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: tc.authMethod,
			})
			c := client.NewAuthClient(env.server.URL, nil, client.WithDPoPKey(env.sdkKey(t)))
			cred, err := c.LoginWithBrowser(context.Background(), &client.BrowserLoginRequest{
				AuthorizationEndpoint: env.server.URL + "/authorize",
				TokenEndpoint:         env.tokenURL,
				ClientID:              reg.ClientID,
				ClientSecret:          reg.ClientSecret,
				Timeout:               5 * time.Second,
				OpenBrowser:           client.FollowRedirects(nil),
			})
			require.NoError(t, err)
			assertBound(t, cred.AccessToken, env.jkt(t))
			require.NotEmpty(t, cred.RefreshToken)

			stored, err := env.refreshStore.GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{Token: cred.RefreshToken})
			require.NoError(t, err)
			if tc.authMethod == "none" {
				require.NotNil(t, stored.Token.Confirmation)
				assert.Equal(t, env.jkt(t), stored.Token.Confirmation.JKT)
			} else {
				assert.True(t, stored.Token.Confirmation.IsEmpty(), "a confidential client's refresh token must not be key-bound")
			}

			newKey := newDPoPE2EEnvKeyOnly(t)
			form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {cred.RefreshToken}, "client_id": {reg.ClientID}}
			req, err := http.NewRequest(http.MethodPost, env.tokenURL, strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("DPoP", newKey.proof(http.MethodPost, env.tokenURL))
			if reg.ClientSecret != "" {
				req.SetBasicAuth(reg.ClientID, reg.ClientSecret)
			}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body := decodeBody(t, resp.Body)
			require.Equal(t, tc.wantStatus, resp.StatusCode, body)

			if tc.wantStatus != http.StatusOK {
				assert.Equal(t, "invalid_grant", body["error"])
				return
			}
			assert.Equal(t, "DPoP", body["token_type"])
			newJKT, err := utils.ComputeKid(&newKey.clientKey.PublicKey, "ES256")
			require.NoError(t, err)
			assertBound(t, body["access_token"].(string), newJKT)
		})
	}
}
