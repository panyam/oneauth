package e2e_test

// Logout revokes refresh tokens, and the access tokens issued with them
// have to stop working too (RFC 7009 §2.1), or a user who logs out
// everywhere after losing a device leaves that device a live token for
// up to its expiry (issue 451).
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://cwe.mitre.org/data/definitions/613.html

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func passwordGrant(t *testing.T, env *TestEnv, email, password string) (accessToken, refreshToken string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"grant_type": "password", "username": email, "password": password})
	resp, err := http.Post(env.BaseURL()+"/api/token", "application/json", strings.NewReader(string(body)))
	require.NoError(t, err)
	tokens := ReadJSON(resp)
	accessToken, _ = tokens["access_token"].(string)
	refreshToken, _ = tokens["refresh_token"].(string)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	return accessToken, refreshToken
}

func listSessions(t *testing.T, env *TestEnv, accessToken string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, env.BaseURL()+"/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func TestLogoutAll_BlacklistsEverySessionsAccessToken(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "logout-all-bl")
	laptop, _ := passwordGrant(t, env, email, password)
	phone, _ := passwordGrant(t, env, email, password)
	require.Equal(t, http.StatusOK, listSessions(t, env, phone))

	req, _ := http.NewRequest(http.MethodPost, env.BaseURL()+"/api/logout-all", nil)
	req.Header.Set("Authorization", "Bearer "+laptop)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	assert.Equal(t, http.StatusUnauthorized, listSessions(t, env, laptop), "the caller's own access token")
	assert.Equal(t, http.StatusUnauthorized, listSessions(t, env, phone), "another session's access token")
}

func TestLogout_BlacklistsThatSessionsAccessToken(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "logout-one-bl")
	laptop, laptopRefresh := passwordGrant(t, env, email, password)
	phone, _ := passwordGrant(t, env, email, password)

	body, _ := json.Marshal(map[string]any{"refresh_token": laptopRefresh})
	resp, err := http.Post(env.BaseURL()+"/api/logout", "application/json", strings.NewReader(string(body)))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	assert.Equal(t, http.StatusUnauthorized, listSessions(t, env, laptop), "the logged-out session's access token")
	assert.Equal(t, http.StatusOK, listSessions(t, env, phone), "another session stays logged in")
}
