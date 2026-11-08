package e2e_test

// End-to-end coverage for ValidateBearer and the token times on TokenInfo
// (issue 456). A resource server holding an open channel, such as massrelay's
// WebSocket, authenticates the opening HTTP request with ValidateToken. Later
// it receives fresh tokens over that channel with no HTTP request around them.
// These tests drive that flow with a real AS, the SDK, and the real
// introspection endpoint. The channel is stood in for by remembering what the
// opening request proved.
//
// References:
//   - RFC 9449 §7.2 (https://www.rfc-editor.org/rfc/rfc9449#section-7.2)
//   - RFC 7662 §2.2 (https://www.rfc-editor.org/rfc/rfc7662#section-2.2)
//   - See: https://github.com/panyam/oneauth/issues/456

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

// channelServer is a resource server whose /open route stands in for a
// WebSocket upgrade: it authenticates the request with ValidateToken and
// records the TokenInfo the handler saw.
type channelServer struct {
	mw     *apiauth.APIMiddleware
	url    string
	opened *apiauth.TokenInfo
}

func newChannelServer(t *testing.T) *channelServer {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	cs := &channelServer{
		url: "http://" + server.Listener.Addr().String(),
	}
	cs.mw = &apiauth.APIMiddleware{
		JWTSecretKey: fullStackJWTSecret,
		JWTIssuer:    fullStackIssuer,
		DPoP:         apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: cs.url}),
	}
	mux.Handle("GET /open", cs.mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.opened = apiauth.GetTokenInfoFromAPIContext(r.Context())
	})))
	server.Start()
	t.Cleanup(server.Close)
	return cs
}

// reauth validates a token sent over the open channel, accepting a bound
// token only for the key the opening request proved.
func (cs *channelServer) reauth(token string) (*apiauth.ValidateBearerResponse, error) {
	return cs.mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{
		Token: token,
		ConfirmBinding: func(_ context.Context, cnf *core.Confirmation) error {
			if !cnf.Equal(cs.opened.Confirmation) {
				return errors.New("token is bound to a different key than this channel")
			}
			return nil
		},
	})
}

func boundClient(t *testing.T, env *fullStackEnv, key *client.DPoPKey) (*client.AuthClient, *client.ClientRegistrationResponse) {
	t.Helper()
	reg := env.register(t, client.ClientRegistrationRequest{
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
		DPoPBoundAccessTokens:   true,
	})
	store := &memCredentialStore{creds: map[string]*client.ServerCredential{}}
	return client.NewAuthClient(env.server.URL, store, client.WithTokenEndpoint("/api/token"), client.WithDPoPKey(key)), reg
}

func TestValidateBearer_E2E_ChannelReauthWithDPoP(t *testing.T) {
	env := newFullStackEnv(t, fullStackOpts{})
	cs := newChannelServer(t)
	sdk, reg := boundClient(t, env, env.sdkKey(t))
	creds := &client.ClientCredentialsRequest{ClientID: reg.ClientID, ClientSecret: reg.ClientSecret}

	first, err := sdk.ClientCredentials(context.Background(), creds)
	require.NoError(t, err)
	resp, err := sdk.HTTPClient().Get(cs.url + "/open")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, cs.opened)
	assert.Equal(t, env.jkt(t), cs.opened.Confirmation.JKT)
	assert.WithinDuration(t, first.ExpiresAt, cs.opened.ExpiresAt, 5*time.Second)
	assert.WithinDuration(t, time.Now(), cs.opened.IssuedAt, 5*time.Second)
	assert.Equal(t, reg.ClientID, cs.opened.ClientID)

	t.Run("a fresh token for the channel's key is accepted", func(t *testing.T) {
		second, err := sdk.ClientCredentials(context.Background(), creds)
		require.NoError(t, err)
		require.NotEqual(t, first.AccessToken, second.AccessToken)

		got, err := cs.reauth(second.AccessToken)

		require.NoError(t, err)
		assert.Equal(t, reg.ClientID, got.Info.Subject)
		assert.False(t, got.Info.ExpiresAt.IsZero())
	})

	t.Run("a token bound to another key is refused", func(t *testing.T) {
		otherKey, err := client.NewDPoPKey()
		require.NoError(t, err)
		other, otherReg := boundClient(t, env, otherKey)
		stolen, err := other.ClientCredentials(context.Background(), &client.ClientCredentialsRequest{
			ClientID: otherReg.ClientID, ClientSecret: otherReg.ClientSecret,
		})
		require.NoError(t, err)

		_, err = cs.reauth(stolen.AccessToken)

		var ae *apiauth.AuthError
		require.ErrorAs(t, err, &ae)
		assert.Equal(t, "invalid_token", ae.Code)
		assert.Equal(t, apiauth.TokenTypeDPoP, ae.Scheme)
	})

	t.Run("without ConfirmBinding a bound token is refused", func(t *testing.T) {
		_, err := cs.mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: first.AccessToken})

		var ae *apiauth.AuthError
		require.ErrorAs(t, err, &ae)
		assert.Equal(t, "invalid_token", ae.Code)
	})
}

// TokenInfo carries exp and iat from the real introspection endpoint, so a
// resource server validating opaque tokens can end a session at exp too.
func TestValidateBearer_E2E_IntrospectionTimes(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("introspection e2e requires in-process servers")
	}
	rsClientID, rsSecret := "e2e-rs-bearer-times", "e2e-rs-bearer-times-secret"
	_, err := env.KeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: rsClientID, Key: []byte(rsSecret), Algorithm: "HS256",
	}})
	require.NoError(t, err)
	email, password := CreateTestUser(t, env, "bearer-times-user")
	accessToken, _ := LoginForTokens(t, env, email, password)
	mw := &apiauth.APIMiddleware{Introspection: &apiauth.IntrospectionValidator{
		IntrospectionURL: env.BaseURL() + "/oauth/introspect", ClientID: rsClientID, ClientSecret: rsSecret,
	}}

	resp, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: accessToken})

	require.NoError(t, err)
	info := resp.Info
	assert.Equal(t, "introspection", info.AuthType)
	assert.True(t, info.ExpiresAt.After(time.Now()), "ExpiresAt = %v", info.ExpiresAt)
	assert.WithinDuration(t, time.Now(), info.IssuedAt, time.Minute)
	assert.NotEmpty(t, info.TokenID)
}
