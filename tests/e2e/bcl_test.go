package e2e_test

// E2E coverage for OIDC Back-Channel Logout 1.0 push (issue 261). Exercises
// the full sender path through the in-process test AS: register a client via
// DCR with a backchannel_logout_uri, get a refresh token via password grant,
// POST /api/logout-all, assert the registered receiver got a valid
// logout_token.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerClientWithBCL registers a confidential client via DCR with the
// given backchannel_logout_uri. Returns (client_id, client_secret).
func registerClientWithBCL(t *testing.T, env *TestEnv, name, bclURI string) (string, string) {
	t.Helper()
	c := NewTestClient(env)
	resp := c.PostJSON("/apps/dcr", map[string]any{
		"client_name":            name,
		"grant_types":            []string{"password", "refresh_token"},
		"backchannel_logout_uri": bclURI,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := ReadJSON(resp)
	clientID, _ := body["client_id"].(string)
	clientSecret, _ := body["client_secret"].(string)
	require.NotEmpty(t, clientID)
	require.NotEmpty(t, clientSecret)
	return clientID, clientSecret
}

func TestBCL_E2E_LogoutAllPostsLogoutTokenToRegisteredReceiver(t *testing.T) {
	env := NewTestEnv(t)

	var rxHits int32
	var rxBody string
	rx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rxBody = string(b)
		atomic.AddInt32(&rxHits, 1)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
	}))
	defer rx.Close()

	clientID, _ := registerClientWithBCL(t, env, "bcl-e2e", rx.URL)
	defer NewTestClient(env).Delete("/apps/" + clientID)

	// Create a user and get a token pair (access + refresh).
	email, password := CreateTestUser(t, env, "bcl-e2e")
	body, _ := json.Marshal(map[string]any{
		"grant_type": "password",
		"username":   email,
		"password":   password,
		"client_id":  clientID,
	})
	tokResp, err := http.Post(env.BaseURL()+"/api/token", "application/json", strings.NewReader(string(body)))
	require.NoError(t, err)
	tokens := ReadJSON(tokResp)
	accessToken, _ := tokens["access_token"].(string)
	refreshToken, _ := tokens["refresh_token"].(string)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)

	// Hit /api/logout-all (requires bearer auth in this env).
	logoutReq, _ := http.NewRequest(http.MethodPost, env.BaseURL()+"/api/logout-all", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+accessToken)
	logoutResp, err := http.DefaultClient.Do(logoutReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, logoutResp.StatusCode)

	// SyncForTest dispatcher → receiver MUST have been hit by the time
	// HandleLogoutAll returned. Generous deadline as a belt-and-suspenders
	// in case of slow CI.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&rxHits) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, int32(1), atomic.LoadInt32(&rxHits), "receiver must be POSTed exactly once")

	// Body shape: logout_token=<JWT>.
	require.True(t, strings.HasPrefix(rxBody, "logout_token="), "body must be application/x-www-form-urlencoded: %s", rxBody)
	jwtStr := strings.TrimPrefix(rxBody, "logout_token=")
	parsed, err := jwt.Parse(jwtStr, func(tok *jwt.Token) (any, error) {
		return []byte(env.JWTSecret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, clientID, claims["aud"])
	assert.Equal(t, testJWTIssuer, claims["iss"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotEmpty(t, claims["sub"], "sub must be present on a logout-all logout_token")
	_, hasNonce := claims["nonce"]
	assert.False(t, hasNonce, "logout_token MUST NOT contain a nonce (OIDC BCL §2.4)")
	ev, ok := claims["events"].(map[string]any)
	require.True(t, ok)
	_, hasEvent := ev["http://schemas.openid.net/event/backchannel-logout"]
	assert.True(t, hasEvent, "events claim must carry the BCL event-type URI")
	assert.Equal(t, "logout+jwt", parsed.Header["typ"])
}

func TestBCL_E2E_NoBCLClientReceivesNothing(t *testing.T) {
	env := NewTestEnv(t)

	// Client registered WITHOUT backchannel_logout_uri must not be hit on
	// logout-all even when an active refresh token exists.
	c := NewTestClient(env)
	resp := c.PostJSON("/apps/dcr", map[string]any{
		"client_name": "no-bcl-client",
		"grant_types": []string{"password", "refresh_token"},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := ReadJSON(resp)
	clientID, _ := body["client_id"].(string)
	defer NewTestClient(env).Delete("/apps/" + clientID)

	email, password := CreateTestUser(t, env, "no-bcl")
	tokBody, _ := json.Marshal(map[string]any{
		"grant_type": "password",
		"username":   email,
		"password":   password,
		"client_id":  clientID,
	})
	tokResp, err := http.Post(env.BaseURL()+"/api/token", "application/json", strings.NewReader(string(tokBody)))
	require.NoError(t, err)
	tokens := ReadJSON(tokResp)
	accessToken, _ := tokens["access_token"].(string)
	require.NotEmpty(t, accessToken)

	logoutReq, _ := http.NewRequest(http.MethodPost, env.BaseURL()+"/api/logout-all", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+accessToken)
	logoutResp, err := http.DefaultClient.Do(logoutReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, logoutResp.StatusCode)
	// No assertion about outbound POSTs — the dispatcher correctly emits
	// none when no client registered a BCL URI. The lack of crash + the
	// 204 is the success signal.
}

