package admin_test

// Tests for the OIDC Back-Channel Logout 1.0 §3.1 registration fields on the
// DCR endpoint — backchannel_logout_uri and backchannel_logout_session_required
// MUST round-trip through register / read / update.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRegistration
// See: https://github.com/panyam/oneauth/issues/261

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registerAppWithBCL(t *testing.T, body string) (handler http.Handler, registrar *admin.AppRegistrar, resp map[string]any) {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	registrar = admin.NewAppRegistrar(ks, admin.NewNoAuth())
	handler = registrar.Handler()

	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())

	resp = map[string]any{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return handler, registrar, resp
}

func TestDCR_BackchannelLogout_RoundTripsThroughRegister(t *testing.T) {
	body := `{
		"client_name":"BCL Client",
		"backchannel_logout_uri":"https://rs.example.com/bcl",
		"backchannel_logout_session_required":true
	}`
	_, registrar, resp := registerAppWithBCL(t, body)

	assert.Equal(t, "https://rs.example.com/bcl", resp["backchannel_logout_uri"])
	assert.Equal(t, true, resp["backchannel_logout_session_required"])

	// Persisted on the underlying AppRegistration too — not just echoed back.
	clientID := resp["client_id"].(string)
	getResp, err := registrar.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: clientID})
	require.NoError(t, err)
	require.NotNil(t, getResp.App)
	assert.Equal(t, "https://rs.example.com/bcl", getResp.App.BackchannelLogoutURI)
	assert.True(t, getResp.App.BackchannelLogoutSessionRequired)
}

func TestDCR_BackchannelLogout_HTTPOutsideLoopback_Rejected(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	handler := registrar.Handler()

	body := `{"client_name":"BCL Client","backchannel_logout_uri":"http://rs.example.com/bcl"}`
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
}

func TestDCR_BackchannelLogout_FragmentRejected(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	handler := registrar.Handler()

	body := `{"client_name":"BCL Client","backchannel_logout_uri":"https://rs.example.com/bcl#frag"}`
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
}

func TestDCR_BackchannelLogout_LoopbackHTTPAllowed(t *testing.T) {
	_, _, resp := registerAppWithBCL(t, `{
		"client_name":"BCL Local",
		"backchannel_logout_uri":"http://localhost:9999/bcl"
	}`)
	assert.Equal(t, "http://localhost:9999/bcl", resp["backchannel_logout_uri"])
}

func TestDCR_BackchannelLogout_EmptyURIDisablesDispatch(t *testing.T) {
	_, registrar, resp := registerAppWithBCL(t, `{"client_name":"No BCL"}`)
	clientID := resp["client_id"].(string)
	getResp, err := registrar.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: clientID})
	require.NoError(t, err)
	assert.Empty(t, getResp.App.BackchannelLogoutURI)
	assert.False(t, getResp.App.BackchannelLogoutSessionRequired)
}
