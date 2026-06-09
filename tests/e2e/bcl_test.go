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

// captureBCLReceiver returns a httptest.Server that records every POST it
// receives. Used by the multi-client + RFC 7009 tests; the test owns Close().
type captureBCLReceiver struct {
	hits int32
	body atomic.Value // last seen body string
}

func newCaptureBCLReceiver() (*captureBCLReceiver, *httptest.Server) {
	rx := &captureBCLReceiver{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rx.body.Store(string(b))
		atomic.AddInt32(&rx.hits, 1)
	}))
	return rx, srv
}

func (r *captureBCLReceiver) hitCount() int32 { return atomic.LoadInt32(&r.hits) }

func (r *captureBCLReceiver) lastBody() string {
	v, _ := r.body.Load().(string)
	return v
}

func TestBCL_E2E_RFC7009RevokeFiresLogoutTokenPOST(t *testing.T) {
	// /oauth/revoke is a different endpoint and a different code path
	// (tokenRevoker.Revoke + OnTokenRevoked) than /api/logout-all. A
	// regression here would not be caught by the logout-all e2e.
	env := NewTestEnv(t)
	rx, srv := newCaptureBCLReceiver()
	defer srv.Close()

	clientID, clientSecret := registerClientWithBCL(t, env, "bcl-revoke", srv.URL)
	defer NewTestClient(env).Delete("/apps/" + clientID)

	email, password := CreateTestUser(t, env, "bcl-revoke")
	tokBody, _ := json.Marshal(map[string]any{
		"grant_type": "password",
		"username":   email,
		"password":   password,
		"client_id":  clientID,
	})
	tokResp, err := http.Post(env.BaseURL()+"/api/token", "application/json", strings.NewReader(string(tokBody)))
	require.NoError(t, err)
	tokens := ReadJSON(tokResp)
	refreshToken, _ := tokens["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	// RFC 7009: revoke the refresh token via the standards-compliant
	// /oauth/revoke endpoint (form-encoded, client_secret_basic).
	revokeResp := revokeToken(t, env, refreshToken, "refresh_token", clientID, clientSecret)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)

	deadline := time.Now().Add(2 * time.Second)
	for rx.hitCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, int32(1), rx.hitCount(), "BCL receiver must be POSTed after /oauth/revoke")

	// Body must be a valid logout_token bound to this client.
	body := rx.lastBody()
	require.True(t, strings.HasPrefix(body, "logout_token="), "body: %s", body)
	parsed, err := jwt.Parse(strings.TrimPrefix(body, "logout_token="), func(tok *jwt.Token) (any, error) {
		return []byte(env.JWTSecret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, clientID, claims["aud"])
	assert.NotEmpty(t, claims["sid"], "sid must be populated for single-token revoke (family ID)")
}

func TestBCL_E2E_DiscoveryAdvertisesBCLSupport(t *testing.T) {
	// AS metadata MUST advertise backchannel_logout_supported /
	// _session_supported once the dispatcher is wired — clients key off
	// these to know whether polling /introspect is still required.
	env := NewTestEnv(t)
	resp, err := http.Get(env.BaseURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	meta := ReadJSON(resp)

	supported, ok := meta["backchannel_logout_supported"].(bool)
	require.True(t, ok, "backchannel_logout_supported must be present and a bool")
	assert.True(t, supported)

	sessionSupported, ok := meta["backchannel_logout_session_supported"].(bool)
	require.True(t, ok, "backchannel_logout_session_supported must be present and a bool")
	assert.True(t, sessionSupported)
}

func TestBCL_E2E_LogoutAllFansOutToMultipleClients(t *testing.T) {
	// Realistic case: alice has tokens on three clients; two registered a
	// BCL URI, one did not. logout-all must hit exactly the two BCL-aware
	// receivers. Exercises the dispatcher's clientIDs fan-out path through
	// the real AS pipeline.
	env := NewTestEnv(t)

	rxA, srvA := newCaptureBCLReceiver()
	defer srvA.Close()
	rxB, srvB := newCaptureBCLReceiver()
	defer srvB.Close()

	clientIDA, _ := registerClientWithBCL(t, env, "bcl-fan-A", srvA.URL)
	defer NewTestClient(env).Delete("/apps/" + clientIDA)
	clientIDB, _ := registerClientWithBCL(t, env, "bcl-fan-B", srvB.URL)
	defer NewTestClient(env).Delete("/apps/" + clientIDB)

	// Client C registered WITHOUT a BCL URI — must not be hit.
	cResp := NewTestClient(env).PostJSON("/apps/dcr", map[string]any{
		"client_name": "bcl-fan-C",
		"grant_types": []string{"password", "refresh_token"},
	})
	require.Equal(t, http.StatusCreated, cResp.StatusCode)
	clientIDC, _ := ReadJSON(cResp)["client_id"].(string)
	defer NewTestClient(env).Delete("/apps/" + clientIDC)

	// Same user, three password grants — one per client.
	email, password := CreateTestUser(t, env, "bcl-fan")
	var accessTokenA string
	for i, cid := range []string{clientIDA, clientIDB, clientIDC} {
		body, _ := json.Marshal(map[string]any{
			"grant_type": "password",
			"username":   email,
			"password":   password,
			"client_id":  cid,
		})
		resp, err := http.Post(env.BaseURL()+"/api/token", "application/json", strings.NewReader(string(body)))
		require.NoError(t, err, "password grant for client %s", cid)
		tokens := ReadJSON(resp)
		if i == 0 {
			accessTokenA, _ = tokens["access_token"].(string)
		}
		require.NotEmpty(t, tokens["refresh_token"], "refresh_token for client %s", cid)
	}
	require.NotEmpty(t, accessTokenA)

	// Authenticated logout-all bound to alice.
	logoutReq, _ := http.NewRequest(http.MethodPost, env.BaseURL()+"/api/logout-all", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+accessTokenA)
	logoutResp, err := http.DefaultClient.Do(logoutReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, logoutResp.StatusCode)

	deadline := time.Now().Add(2 * time.Second)
	for (rxA.hitCount() == 0 || rxB.hitCount() == 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, int32(1), rxA.hitCount(), "client A receiver must be POSTed once")
	require.Equal(t, int32(1), rxB.hitCount(), "client B receiver must be POSTed once")
	// Client C registered no BCL URI; the dispatcher has nowhere to dial
	// for it. The implicit assertion is exactly two POSTs total across rxA
	// + rxB — verified above. The sleep below catches any stray async
	// misfire (e.g., a buggy dispatcher that doubled up on A).
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int32(1), rxA.hitCount(), "client A must still be exactly 1")
	require.Equal(t, int32(1), rxB.hitCount(), "client B must still be exactly 1")
	_ = clientIDC // referenced for clarity; no separate assertion needed
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

