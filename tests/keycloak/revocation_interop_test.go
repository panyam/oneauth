package keycloak_test

// Revocation (RFC 7009) compared with Keycloak, issue 88: a client asking
// to revoke another client's token, and a request with no token, get the
// same answer from both servers.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

func revoke(t *testing.T, endpoint string, form url.Values, user, pass string) answer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	e, _ := body["error"].(string)
	return answer{Status: resp.StatusCode, Error: e}
}

// oneauthRevocationMirror serves POST /revoke with the realm's two
// confidential clients, and mints access tokens for them.
func oneauthRevocationMirror(t *testing.T) (endpoint string, mint func(clientID string) string) {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	for id, secret := range map[string]string{confidentialClientID: confidentialClientSecret, audienceClientID: audienceClientSecret} {
		_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: id, Key: []byte(secret), Algorithm: "HS256"}})
		require.NoError(t, err)
	}
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore: ks, Blacklist: core.NewInMemoryBlacklist(),
		SigningKey: []byte("keycloak-mirror-jwt-secret-32chr"), SigningAlg: "HS256", Issuer: "oneauth-keycloak-mirror",
	})
	mux := http.NewServeMux()
	mux.Handle("POST /revoke", oa.RevocationHTTPHandler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL + "/revoke", func(clientID string) string {
		tok, err := oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: clientID, ClientID: clientID})
		require.NoError(t, err)
		return tok.Token
	}
}

func TestKeycloakCompare_Revocation(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)
	kcRevoke := strings.TrimSuffix(cfg.TokenEndpoint, "/token") + "/revoke"
	mirror, mint := oneauthRevocationMirror(t)

	kcToken := getClientCredentialsToken(t, cfg.TokenEndpoint, confidentialClientID, confidentialClientSecret).AccessToken

	cases := []struct {
		name              string
		keycloak, oneauth url.Values
		want              answer
	}{
		{
			name:     "another client's access token",
			keycloak: url.Values{"token": {kcToken}},
			oneauth:  url.Values{"token": {mint(confidentialClientID)}},
			want:     answer{Status: http.StatusBadRequest, Error: "invalid_request"},
		},
		{
			name:     "no token",
			keycloak: url.Values{"x": {"1"}},
			oneauth:  url.Values{"x": {"1"}},
			want:     answer{Status: http.StatusBadRequest, Error: "invalid_request"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Both requests come from the realm's other confidential client.
			assert.Equal(t, c.want, revoke(t, kcRevoke, c.keycloak, audienceClientID, audienceClientSecret), "keycloak")
			assert.Equal(t, c.want, revoke(t, mirror, c.oneauth, audienceClientID, audienceClientSecret), "oneauth")
		})
	}
}
