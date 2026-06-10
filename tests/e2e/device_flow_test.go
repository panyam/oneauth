package e2e_test

// End-to-end RFC 8628 Device Authorization Grant test against an
// in-process oneauth AS. Drives the full arc that #117, #266, #267, and
// #268 ship across:
//
//	POST /device/authorize          — wire protocol (#117)
//	GET  /device                    — code entry form (#267)
//	POST /device                    — submit code, redirect to consent (#267)
//	GET  /device/approve            — consent screen (#267)
//	POST /device/approve            — approve / deny decision (#267)
//	POST /api/token                 — grant_type=device_code + confidential-client auth (#117 / #266)
//
// Catches wire-format drift across all four PRs that the per-handler unit
// tests cannot — those test each handler against synthetic stores; this
// test drives one shared store through every handler the way a real
// device-and-browser pair would.
//
// Why a hand-rolled fixture instead of TestEnv: TestEnv mounts the legacy
// /api/token wired against a JSON request shape with no device-grant
// branch; adding the device flow to it would mean threading new fields
// through every other e2e test. A focused fixture keeps the device-flow
// arc isolated and the failure mode narrow.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	deviceTestJWTSecret   = "device-e2e-jwt-secret-32chars!!!"
	deviceTestJWTIssuer   = "oneauth-device-e2e"
	deviceTestAdminKey    = "device-e2e-admin-key"
	deviceTestCSRFToken   = "device-e2e-csrf-token" // fixed for the shim — real CSRF is exercised by httpauth_test
	deviceTestSubjectHdr  = "X-Test-Subject"
	deviceTestSlowDownGap = -time.Hour // backdate LastPolledAt past the polling interval
)

// deviceFlowEnv is the per-test fixture: a single in-process AS wired
// with /device/authorize, the four /device + /device/approve verification
// routes, and /api/token. Stores are in-memory and dedicated per test.
type deviceFlowEnv struct {
	t              *testing.T
	server         *httptest.Server
	apiAuth        *apiauth.APIAuth
	appRegistrar   *admin.AppRegistrar
	deviceStore    core.DeviceAuthorizationStore
	appStore       core.AppRegistrationStore
	keyStore       *keys.InMemoryKeyStore
	expiry         time.Duration // applied to DeviceAuthorizationHandler.Expiry
}

func newDeviceFlowEnv(t *testing.T, expiry time.Duration) *deviceFlowEnv {
	t.Helper()
	env := &deviceFlowEnv{t: t, expiry: expiry}

	env.deviceStore = core.NewInMemoryDeviceAuthorizationStore()
	env.appStore = core.NewInMemoryAppStore()
	env.keyStore = keys.NewInMemoryKeyStore()

	env.appRegistrar = admin.NewAppRegistrarWithStore(env.keyStore, admin.NewAPIKeyAuth(deviceTestAdminKey), env.appStore)

	env.apiAuth = &apiauth.APIAuth{
		JWTSecretKey:    deviceTestJWTSecret,
		JWTIssuer:       deviceTestJWTIssuer,
		ClientKeyStore:  env.keyStore,
		DeviceAuthStore: env.deviceStore,
		AppStore:        env.appStore, // enables RFC 8628 §3.4 confidential-client enforcement
	}

	mux := http.NewServeMux()

	devAuthHandler := &apiauth.DeviceAuthorizationHandler{
		Store:               env.deviceStore,
		VerificationURI:     "", // populated after server starts
		Expiry:              env.expiry,
		ClientAuthenticator: nil, // public + confidential clients both work; confidential auth happens on redemption per #266
	}
	mux.Handle("POST /device/authorize", devAuthHandler)

	verifier := &apiauth.DeviceVerificationHandler{
		Store:    env.deviceStore,
		AppStore: env.appStore,
		Approve: func(r *http.Request, userCode, subject string, scopes []string) error {
			return env.apiAuth.ApproveDeviceAuthorization(r, userCode, subject, scopes)
		},
		Deny: func(r *http.Request, userCode string) error {
			return env.apiAuth.DenyDeviceAuthorization(r, userCode)
		},
		// Option B (issue 276): the shim — login state lives in a request
		// header so the test fixture stays free of localauth + session
		// dependencies. Real-httpauth session and CSRF middleware are
		// covered by httpauth_test and device_verification_handler_test
		// respectively; this test's job is wire-format drift across the
		// four shipped PRs (#117 / #266 / #267 / #268).
		SubjectFromRequest:   func(r *http.Request) string { return r.Header.Get(deviceTestSubjectHdr) },
		CSRFTokenFromRequest: func(*http.Request) string { return deviceTestCSRFToken },
	}
	mux.HandleFunc("GET /device", verifier.Form)
	mux.HandleFunc("POST /device", verifier.Submit)
	mux.HandleFunc("GET /device/approve", verifier.Consent)
	mux.HandleFunc("POST /device/approve", verifier.Decide)

	mux.Handle("POST /api/token", env.apiAuth)

	env.server = httptest.NewServer(mux)
	t.Cleanup(env.server.Close)

	devAuthHandler.VerificationURI = env.server.URL + "/device"
	return env
}

// registerClient drives AppRegistrar.Register directly (bypassing the
// DCR HTTP wrapper) and returns the client_id + secret. authMethod is
// "client_secret_post" / "client_secret_basic" / "none".
func (e *deviceFlowEnv) registerClient(authMethod string) (clientID, secret string) {
	e.t.Helper()
	resp, err := e.appRegistrar.Register(context.Background(), &admin.RegisterRequest{
		Metadata: &admin.DCRRequest{
			ClientName:              "device-e2e-client",
			TokenEndpointAuthMethod: authMethod,
		},
		IssuerBaseURL: e.server.URL,
	})
	require.NoError(e.t, err)
	require.NotNil(e.t, resp)
	require.NotNil(e.t, resp.Registration)
	return resp.Registration.ClientID, resp.Registration.ClientSecret
}

// deviceAuthorize posts to /device/authorize and returns the parsed body.
func (e *deviceFlowEnv) deviceAuthorize(clientID string) map[string]any {
	e.t.Helper()
	form := url.Values{"client_id": {clientID}, "scope": {"read"}}
	resp, err := http.Post(e.server.URL+"/device/authorize", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(e.t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(e.t, http.StatusOK, resp.StatusCode, "device authorize failed: %s", body)
	var parsed map[string]any
	require.NoError(e.t, json.Unmarshal(body, &parsed))
	return parsed
}

// browserClient is the user's browser that drives the consent UI. The
// shim's subject header is set on every request so the verifier sees a
// logged-in user; cookiejar is enabled so any future real-session work
// migrates cleanly.
func (e *deviceFlowEnv) browserClient(subject string) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Set(deviceTestSubjectHdr, subject)
			return nil
		},
		Transport: subjectHeaderTransport{subject: subject, base: http.DefaultTransport},
	}
}

// subjectHeaderTransport stamps the test-subject header on every outbound
// request the browser client makes. Lifts the shim into one place so each
// scenario's HTTP calls stay readable.
type subjectHeaderTransport struct {
	subject string
	base    http.RoundTripper
}

func (t subjectHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(deviceTestSubjectHdr, t.subject)
	return t.base.RoundTrip(req)
}

// driveConsentUI walks GET /device → POST /device → GET /device/approve
// → POST /device/approve. action is "approve" or "deny". Returns the
// final response (the rendered "return to your device" page).
func (e *deviceFlowEnv) driveConsentUI(client *http.Client, userCode, action string) *http.Response {
	e.t.Helper()

	// GET /device — sanity check the form renders.
	resp, err := client.Get(e.server.URL + "/device")
	require.NoError(e.t, err)
	require.Equal(e.t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// POST /device — submit the user_code. Authenticated subject means
	// the handler redirects to /device/approve, not the login page.
	resp, err = client.PostForm(e.server.URL+"/device", url.Values{
		"user_code":  {userCode},
		"csrf_token": {deviceTestCSRFToken},
	})
	require.NoError(e.t, err)
	require.Equal(e.t, http.StatusOK, resp.StatusCode, "post /device followed to %s", resp.Request.URL.Path)
	// The post is followed through the redirect to /device/approve (GET).
	require.Equal(e.t, "/device/approve", resp.Request.URL.Path)
	resp.Body.Close()

	// POST /device/approve — the user clicks Approve or Deny.
	resp, err = client.PostForm(e.server.URL+"/device/approve", url.Values{
		"user_code":  {userCode},
		"action":     {action},
		"csrf_token": {deviceTestCSRFToken},
	})
	require.NoError(e.t, err)
	require.Equal(e.t, http.StatusOK, resp.StatusCode, "post /device/approve action=%s failed", action)
	return resp
}

// pollToken posts grant_type=device_code with the supplied credentials.
// Returns the HTTP status and the parsed body.
func (e *deviceFlowEnv) pollToken(form url.Values) (int, map[string]any) {
	e.t.Helper()
	resp, err := http.Post(e.server.URL+"/api/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(e.t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if len(body) > 0 {
		_ = json.Unmarshal(body, &parsed)
	}
	return resp.StatusCode, parsed
}

// resetPollClock backdates LastPolledAt so an immediate next poll is
// allowed without slow_down. RFC 8628 §3.5 the AS rejects polls that
// arrive faster than the advertised interval; tests cannot afford the
// 5-second wait between polls so they manipulate the store directly.
func (e *deviceFlowEnv) resetPollClock(deviceCode string) {
	e.t.Helper()
	_, err := e.deviceStore.UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
		DeviceCode: deviceCode,
		PolledAt:   time.Now().Add(deviceTestSlowDownGap),
		SlowDown:   false,
	})
	require.NoError(e.t, err)
}

// TestDeviceFlow_HappyPath_ConfidentialClient drives the full RFC 8628
// arc end-to-end for a confidential client that authenticates on
// redemption per RFC 8628 §3.4 + issue 266.
func TestDeviceFlow_HappyPath_ConfidentialClient(t *testing.T) {
	env := newDeviceFlowEnv(t, 0)
	clientID, secret := env.registerClient("client_secret_post")
	require.NotEmpty(t, secret, "confidential client MUST receive a secret")

	auth := env.deviceAuthorize(clientID)
	deviceCode := auth["device_code"].(string)
	userCode := auth["user_code"].(string)

	browser := env.browserClient("alice")
	env.driveConsentUI(browser, userCode, "approve")

	env.resetPollClock(deviceCode)
	status, body := env.pollToken(url.Values{
		"grant_type":    {apiauth.DeviceCodeGrantType},
		"device_code":   {deviceCode},
		"client_id":     {clientID},
		"client_secret": {secret},
	})
	require.Equal(t, http.StatusOK, status, "approved + authenticated poll MUST mint a token; got body=%v", body)
	assert.NotEmpty(t, body["access_token"], "access_token issued")
	assert.Equal(t, "Bearer", body["token_type"])
}

// TestDeviceFlow_Deny_ReturnsAccessDenied drives the explicit-deny
// branch: the user clicks Deny, the next poll MUST surface
// access_denied per RFC 8628 §3.5.
func TestDeviceFlow_Deny_ReturnsAccessDenied(t *testing.T) {
	env := newDeviceFlowEnv(t, 0)
	clientID, secret := env.registerClient("client_secret_post")

	auth := env.deviceAuthorize(clientID)
	deviceCode := auth["device_code"].(string)
	userCode := auth["user_code"].(string)

	browser := env.browserClient("alice")
	env.driveConsentUI(browser, userCode, "deny")

	env.resetPollClock(deviceCode)
	status, body := env.pollToken(url.Values{
		"grant_type":    {apiauth.DeviceCodeGrantType},
		"device_code":   {deviceCode},
		"client_id":     {clientID},
		"client_secret": {secret},
	})
	require.Equal(t, http.StatusBadRequest, status, "denied auth MUST NOT mint a token")
	assert.Equal(t, "access_denied", body["error"])
}

// TestDeviceFlow_NoClientCredentials_ReturnsInvalidClient pins the
// issue-266 security review fix: a confidential client (anything other
// than token_endpoint_auth_method=none) MUST authenticate on the
// redemption call. Polling with the right device_code but no secret
// returns invalid_client per RFC 6749 §5.2.
func TestDeviceFlow_NoClientCredentials_ReturnsInvalidClient(t *testing.T) {
	env := newDeviceFlowEnv(t, 0)
	clientID, _ := env.registerClient("client_secret_post")

	auth := env.deviceAuthorize(clientID)
	deviceCode := auth["device_code"].(string)
	userCode := auth["user_code"].(string)

	browser := env.browserClient("alice")
	env.driveConsentUI(browser, userCode, "approve")

	env.resetPollClock(deviceCode)
	status, body := env.pollToken(url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {clientID},
		// no client_secret — confidential client must NOT be redeemable
	})
	require.Equal(t, http.StatusUnauthorized, status,
		"confidential client redemption without credentials MUST be rejected (RFC 8628 §3.4 / issue 266)")
	assert.Equal(t, "invalid_client", body["error"], "got body=%v", body)
}

// TestDeviceFlow_ExpiredCode_ReturnsExpiredToken pins RFC 8628 §3.5
// expired_token: once the authorization window passes, polling MUST
// return expired_token even on otherwise-valid credentials.
func TestDeviceFlow_ExpiredCode_ReturnsExpiredToken(t *testing.T) {
	// Tight 100ms window — sleep past it before the first poll.
	env := newDeviceFlowEnv(t, 100*time.Millisecond)
	clientID, secret := env.registerClient("client_secret_post")

	auth := env.deviceAuthorize(clientID)
	deviceCode := auth["device_code"].(string)

	time.Sleep(200 * time.Millisecond)

	status, body := env.pollToken(url.Values{
		"grant_type":    {apiauth.DeviceCodeGrantType},
		"device_code":   {deviceCode},
		"client_id":     {clientID},
		"client_secret": {secret},
	})
	require.Equal(t, http.StatusBadRequest, status, "expired authorization MUST NOT mint a token")
	assert.Equal(t, "expired_token", body["error"], "got body=%v", body)
}

// TestDeviceFlow_PublicClient_NoAuthRequired pins the public-client
// branch: a client registered with token_endpoint_auth_method=none MUST
// redeem successfully without any client_secret. This is the path real
// CLIs (oneauth token device, gcloud auth, GitHub CLI) take.
func TestDeviceFlow_PublicClient_NoAuthRequired(t *testing.T) {
	env := newDeviceFlowEnv(t, 0)
	clientID, _ := env.registerClient("none")
	// The registrar still issues a symmetric secret on the none path
	// (#266 only governs token-endpoint enforcement, not registration).
	// What we pin here is that the token endpoint does NOT require it.

	auth := env.deviceAuthorize(clientID)
	deviceCode := auth["device_code"].(string)
	userCode := auth["user_code"].(string)

	browser := env.browserClient("alice")
	env.driveConsentUI(browser, userCode, "approve")

	env.resetPollClock(deviceCode)
	status, body := env.pollToken(url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	})
	require.Equal(t, http.StatusOK, status, "public client poll MUST mint a token without credentials; body=%v", body)
	assert.NotEmpty(t, body["access_token"], "access_token issued")
}

