package e2e_test

// E2E test for `private_key_jwt` client authentication on the token
// endpoint (RFC 7521 §4.2 + RFC 7523 §2.2 + OIDC Core §9). Mirrors
// client_credentials_test.go but the client authenticates with a
// signed assertion instead of a shared secret.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// TestPrivateKeyJWT_E2E_FullFlow registers a client with an RSA public
// key, mints a client_assertion via the SDK helper, exchanges it for an
// access token at /api/token using the client_credentials grant, and
// verifies the token works on a protected endpoint with sub=client_id.
//
// See: https://www.rfc-editor.org/rfc/rfc7523#section-2.2
func TestPrivateKeyJWT_E2E_FullFlow(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("private_key_jwt e2e requires in-process servers")
	}

	const clientID = "e2e-pkjwt-client"
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	require.NoError(t, env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       pubPEM,
		Algorithm: "RS256",
	}))

	priv, err := utils.ParsePrivateKeyPEM(privPEM)
	require.NoError(t, err)

	tokenURL := env.BaseURL() + "/api/token"
	assertion, err := client.MintClientAssertion(clientID, tokenURL, client.ClientAssertionConfig{
		PrivateKey: priv,
		SigningAlg: "RS256",
	})
	require.NoError(t, err)

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"read write"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token endpoint should accept private_key_jwt; body=%s", body)

	var tokenResp map[string]any
	require.NoError(t, json.Unmarshal(body, &tokenResp))
	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok, "response must contain access_token")
	assert.Equal(t, "Bearer", tokenResp["token_type"])
	assert.Nil(t, tokenResp["refresh_token"], "client_credentials must not return refresh_token")

	// Token must work on a protected endpoint, with sub=client_id.
	req, _ := http.NewRequest(http.MethodGet, env.BaseURL()+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	meResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer meResp.Body.Close()
	require.Equal(t, http.StatusOK, meResp.StatusCode)

	meBody, _ := io.ReadAll(meResp.Body)
	var meResult map[string]any
	require.NoError(t, json.Unmarshal(meBody, &meResult))
	assert.Equal(t, clientID, meResult["user_id"], "sub claim should be the client_id")
}

// TestPrivateKeyJWT_E2E_SDKHelper exercises the AuthClient SDK path
// (ClientCredentialsTokenWithAssertion) — the path most consumers will
// use. Confirms the SDK and the AS together produce a usable token.
func TestPrivateKeyJWT_E2E_SDKHelper(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("private_key_jwt e2e requires in-process servers")
	}

	const clientID = "e2e-pkjwt-sdk-client"
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	require.NoError(t, env.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       pubPEM,
		Algorithm: "RS256",
	}))
	priv, err := utils.ParsePrivateKeyPEM(privPEM)
	require.NoError(t, err)

	store := &memCredentialStore{creds: make(map[string]*client.ServerCredential)}
	authClient := client.NewAuthClient(env.BaseURL(), store,
		client.WithTokenEndpoint("/api/token"))

	cred, err := authClient.ClientCredentialsTokenWithAssertion(clientID, client.ClientAssertionConfig{
		PrivateKey: priv,
		SigningAlg: "RS256",
	}, []string{"read"})
	require.NoError(t, err)
	require.NotEmpty(t, cred.AccessToken)
}
