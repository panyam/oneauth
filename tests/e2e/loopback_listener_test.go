package e2e_test

// End-to-end test of the caller-owned loopback listener against oneauth's own
// AS, with redirect_uri validation turned on. The shared e2e fixture mounts
// /authorize without an AppStore, so it accepts any redirect; this one wires
// OneAuth.AppStore that DCR writes into, which makes /authorize match the
// registered redirect_uri exactly, except for the port on a loopback http
// redirect (RFC 8252 §7.3, issue 389).
//
// Flow: bind a listener → DCR with LoopbackRedirectURI(l.Addr()) →
// LoginWithBrowser{Listener: l} → /authorize → loopback → /api/token.
//
// References:
//   - RFC 8252 §7.3 (https://www.rfc-editor.org/rfc/rfc8252#section-7.3)
//   - RFC 7591 (https://www.rfc-editor.org/rfc/rfc7591)
//   - See: https://github.com/panyam/oneauth/issues/387
//   - See: https://github.com/panyam/oneauth/issues/389

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

func newStrictRedirectAS(t *testing.T) *httptest.Server {
	t.Helper()
	keyStore := keys.NewInMemoryKeyStore()
	appStore := core.NewInMemoryAppStore()
	// Open DCR, as MCP clients expect of the servers they register with.
	registrar := admin.NewAppRegistrarWithStore(keyStore, admin.NewNoAuth(), appStore)

	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:               keyStore,
		SigningKey:             []byte("loopback-e2e-jwt-secret-32-chars"),
		SigningAlg:             "HS256",
		Issuer:                 "oneauth-loopback-e2e",
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
		AppStore:               appStore,
	})

	mux := http.NewServeMux()
	mux.Handle("POST /api/token", apiauth.NewTokenEndpointHandler(oa))
	mux.Handle("/apps/", registrar.Handler())
	mux.Handle("/apps/dcr", registrar.Handler())
	apiauth.MountAuthorize(mux, apiauth.AuthorizeMountConfig{
		OneAuth:              oa,
		IssuerURL:            "oneauth-loopback-e2e",
		SubjectFromRequest:   func(r *http.Request) string { return "" },
		CSRFTokenFromRequest: func(r *http.Request) string { return "" },
		AutoApproveSubject:   "loopback-e2e-user",
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func registerLoopbackClient(t *testing.T, as *httptest.Server, redirect string) string {
	t.Helper()
	resp, err := client.RegisterClient(as.URL+"/apps/dcr", client.ClientRegistrationRequest{
		ClientName:              "loopback-e2e",
		RedirectURIs:            []string{redirect},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}, nil)
	require.NoError(t, err)
	return resp.ClientID
}

func loopbackLoginRequest(as *httptest.Server, clientID string) *client.BrowserLoginRequest {
	return &client.BrowserLoginRequest{
		AuthorizationEndpoint: as.URL + "/authorize",
		TokenEndpoint:         as.URL + "/api/token",
		ClientID:              clientID,
		Timeout:               5 * time.Second,
		OpenBrowser:           client.FollowRedirects(nil),
	}
}

func TestE2E_LoopbackListener_DCRExactRedirect(t *testing.T) {
	as := newStrictRedirectAS(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	clientID := registerLoopbackClient(t, as, client.LoopbackRedirectURI(l.Addr()))

	req := loopbackLoginRequest(as, clientID)
	req.Listener = l
	cred, err := client.NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, cred.AccessToken)
}

// The IP-literal registration RFC 8252 §8.3 recommends, sent via RedirectURI.
func TestE2E_LoopbackListener_RedirectURIOverride(t *testing.T) {
	as := newStrictRedirectAS(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	redirect := "http://" + l.Addr().String() + "/oauth/done"
	clientID := registerLoopbackClient(t, as, redirect)

	req := loopbackLoginRequest(as, clientID)
	req.Listener = l
	req.RedirectURI = redirect
	cred, err := client.NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, cred.AccessToken)
}

// A client that registered a loopback redirect once can log in on whatever
// port the OS hands it, without a caller-owned listener (RFC 8252 §7.3).
func TestE2E_LoopbackListener_EphemeralPortMatchesRegistration(t *testing.T) {
	as := newStrictRedirectAS(t)
	clientID := registerLoopbackClient(t, as, "http://localhost:1/callback")

	cred, err := client.NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), loopbackLoginRequest(as, clientID))
	require.NoError(t, err)
	assert.NotEmpty(t, cred.AccessToken)
}

// A redirect on a different loopback host than the registration (localhost
// vs 127.0.0.1) is refused by oneauth's /authorize, since only the port is
// relaxed, and FollowRedirects surfaces that at once rather than letting the
// login wait out its timeout.
func TestE2E_LoopbackListener_UnregisteredRedirectFailsFast(t *testing.T) {
	as := newStrictRedirectAS(t)
	clientID := registerLoopbackClient(t, as, "http://127.0.0.1:1/callback")

	req := loopbackLoginRequest(as, clientID)
	req.Timeout = 30 * time.Second
	start := time.Now()
	_, err := client.NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "should fail fast, not wait for the timeout")
	assert.Contains(t, err.Error(), "authorization endpoint answered 4")
}
