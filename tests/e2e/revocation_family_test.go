package e2e_test

// Revoking a refresh token at /oauth/revoke also invalidates the access
// tokens issued from the same grant, including the ones minted by
// refreshing before the revocation.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://github.com/panyam/oneauth/issues/436

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func postJSONToken(t *testing.T, env *TestEnv, body map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(env.BaseURL()+"/api/token", "application/json", strings.NewReader(string(b)))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return ReadJSON(resp)
}

func TestRevocation_E2E_RefreshTokenTakesItsAccessTokens(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "revoke-family")
	clientID, clientSecret := RegisterApp(t, env, "revoke-family.example.com")
	defer NewTestClient(env).Delete("/apps/" + clientID)

	login := postJSONToken(t, env, map[string]any{"grant_type": "password", "username": email, "password": password})
	refreshed := postJSONToken(t, env, map[string]any{"grant_type": "refresh_token", "refresh_token": login["refresh_token"]})
	for _, tok := range []any{login["access_token"], refreshed["access_token"]} {
		require.Equal(t, true, introspectToken(t, env, tok.(string), clientID, clientSecret)["active"])
	}

	resp := revokeToken(t, env, refreshed["refresh_token"].(string), "refresh_token", clientID, clientSecret)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, false, introspectToken(t, env, login["access_token"].(string), clientID, clientSecret)["active"], "login access token")
	assert.Equal(t, false, introspectToken(t, env, refreshed["access_token"].(string), clientID, clientSecret)["active"], "refreshed access token")
}
