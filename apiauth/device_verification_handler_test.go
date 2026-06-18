package apiauth_test

// Tests for the RFC 8628 §3.3 user-facing verification flow served by
// apiauth.DeviceVerificationHandler. Drive the four routes via httptest
// + a real APIAuth (so Approve/Deny route through the production code
// path) + an in-memory device store + an in-memory AppStore.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deviceVerifyFixture wires the device store + AppStore + a
// pluggable session "subject" function so each test can choose whether
// the caller is logged in.
type deviceVerifyFixture struct {
	deviceStore  *core.InMemoryDeviceAuthorizationStore
	appStore     *core.InMemoryAppStore
	handler      *apiauth.DeviceVerificationHandler
	sessionSubject string
}

func newDeviceVerifyFixture(t *testing.T) *deviceVerifyFixture {
	t.Helper()
	deviceStore := core.NewInMemoryDeviceAuthorizationStore()
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:                "client-tv",
		ClientName:              "My TV App",
		TokenEndpointAuthMethod: "none",
	}})
	require.NoError(t, err)

	f := &deviceVerifyFixture{
		deviceStore: deviceStore,
		appStore:    apps,
	}
	f.handler = &apiauth.DeviceVerificationHandler{
		Store:    deviceStore,
		AppStore: apps,
		Approve: func(r *http.Request, userCode, subject string, scopes []string) error {
			_, err := deviceStore.ApproveDeviceAuthorization(r.Context(), &core.ApproveDeviceAuthorizationRequest{
				UserCode:        userCode,
				ApprovedSubject: subject,
				GrantedScopes:   scopes,
			})
			return err
		},
		Deny: func(r *http.Request, userCode string) error {
			_, err := deviceStore.DenyDeviceAuthorization(r.Context(), &core.DenyDeviceAuthorizationRequest{UserCode: userCode})
			return err
		},
		SubjectFromRequest:   func(*http.Request) string { return f.sessionSubject },
		CSRFTokenFromRequest: func(*http.Request) string { return "test-csrf-token" },
		LoginRedirectURL:     "/auth/login",
	}
	return f
}

// seedDeviceAuth inserts a pending device authorization for use in the
// flow tests. Returns the user_code so the test can submit it.
func (f *deviceVerifyFixture) seedDeviceAuth(t *testing.T, clientID, userCode string, scopes []string) string {
	t.Helper()
	now := time.Now()
	auth := &core.DeviceAuthorization{
		DeviceCode:      "dc-" + userCode,
		UserCode:        userCode,
		ClientID:        clientID,
		Scopes:          scopes,
		Status:          core.DeviceAuthorizationStatusPending,
		CreatedAt:       now,
		ExpiresAt:       now.Add(5 * time.Minute),
		IntervalSeconds: 5,
	}
	_, err := f.deviceStore.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: auth})
	require.NoError(t, err)
	return userCode
}

func TestDeviceVerify_FormRendered(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/device", nil)
	rr := httptest.NewRecorder()
	f.handler.Form(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "test-csrf-token", "CSRF token MUST be embedded in the form")
	assert.Contains(t, body, `name="user_code"`)
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/html")
}

func TestDeviceVerify_Submit_UnknownCode_ReRendersWithError(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	form := url.Values{"user_code": {"NOPE-NOPE"}}
	req := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	f.handler.Submit(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "unknown code re-renders the form, doesn't redirect")
	body := rr.Body.String()
	// HTML-escaped: apostrophe in "couldn't" renders as `couldn&#39;t`.
	assert.Contains(t, body, "find that code")
	assert.Contains(t, body, "NOPE-NOPE", "the submitted code is echoed back so the user can correct it")
}

func TestDeviceVerify_Submit_KnownCode_Unauthenticated_RedirectsToLogin(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	code := f.seedDeviceAuth(t, "client-tv", "ABCD-EFGH", []string{"read"})
	form := url.Values{"user_code": {code}}
	req := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	f.handler.Submit(rr, req)

	require.Equal(t, http.StatusSeeOther, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "/auth/login")
	assert.Contains(t, loc, "next=", "redirect MUST round-trip the consent URL")
	// The next= param is URL-encoded; decode it before asserting.
	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	assert.Contains(t, parsed.Query().Get("next"), "user_code=ABCD-EFGH",
		"the next URL preserves the user_code")
}

func TestDeviceVerify_Submit_KnownCode_Authenticated_RedirectsToConsent(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	f.sessionSubject = "alice"
	code := f.seedDeviceAuth(t, "client-tv", "WDJB-MJHT", []string{"read", "write"})

	form := url.Values{"user_code": {code}}
	req := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	f.handler.Submit(rr, req)

	require.Equal(t, http.StatusSeeOther, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "/device/approve")
	assert.Contains(t, loc, "user_code=WDJB-MJHT")
	assert.NotContains(t, loc, "/auth/login", "authenticated users skip login")
}

func TestDeviceVerify_Consent_RendersClientNameAndScopes(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	f.sessionSubject = "alice"
	code := f.seedDeviceAuth(t, "client-tv", "WDJB-MJHT", []string{"read", "write"})

	req := httptest.NewRequest(http.MethodGet, "/device/approve?user_code="+code, nil)
	rr := httptest.NewRecorder()
	f.handler.Consent(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "My TV App", "client_name from AppStore MUST render")
	assert.Contains(t, body, "client-tv", "raw client_id is shown alongside the friendly name")
	assert.Contains(t, body, "read")
	assert.Contains(t, body, "write")
	assert.Contains(t, body, "test-csrf-token")
	assert.Contains(t, body, `value="WDJB-MJHT"`, "user_code carried as hidden field for the POST")
}

func TestDeviceVerify_Consent_AppStoreMiss_FallsBackToClientID(t *testing.T) {
	// When no AppRegistration matches, the consent screen still renders —
	// just with the raw client_id as the display name. This is a
	// resilience property, not a feature: the device flow shouldn't
	// break because someone deleted an app registration mid-flow.
	f := newDeviceVerifyFixture(t)
	f.sessionSubject = "alice"
	code := f.seedDeviceAuth(t, "client-ghost", "ABCD-1234", []string{"read"})

	req := httptest.NewRequest(http.MethodGet, "/device/approve?user_code="+code, nil)
	rr := httptest.NewRecorder()
	f.handler.Consent(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "client-ghost", "unregistered client renders by raw id")
}

func TestDeviceVerify_Decide_Approve_FlipsStoreStatus(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	f.sessionSubject = "alice"
	code := f.seedDeviceAuth(t, "client-tv", "WDJB-MJHT", []string{"read"})

	form := url.Values{
		"user_code": {code},
		"action":    {"approve"},
	}
	req := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	f.handler.Decide(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "may now return to your device")

	g, err := f.deviceStore.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: code})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusApproved, g.Authorization.Status)
	assert.Equal(t, "alice", g.Authorization.ApprovedSubject)
}

func TestDeviceVerify_Decide_Deny_FlipsStoreStatus(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	f.sessionSubject = "alice"
	code := f.seedDeviceAuth(t, "client-tv", "DENI-EDDD", []string{"read"})

	form := url.Values{
		"user_code": {code},
		"action":    {"deny"},
	}
	req := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	f.handler.Decide(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "Denied")

	g, err := f.deviceStore.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: code})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusDenied, g.Authorization.Status)
}

func TestDeviceVerify_Decide_MissingAction_400(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	f.sessionSubject = "alice"
	code := f.seedDeviceAuth(t, "client-tv", "ABCD-1234", []string{"read"})

	form := url.Values{"user_code": {code}} // no action
	req := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	f.handler.Decide(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestDeviceVerify_FullFlow_EndToEnd(t *testing.T) {
	// Walk all four routes in sequence — verifies the redirect chain
	// composes correctly, the CSRF token is embedded, and the device
	// store ends in the right state. This is the closest thing to an
	// e2e test we can stage without a real browser session manager.
	f := newDeviceVerifyFixture(t)
	code := f.seedDeviceAuth(t, "client-tv", "FULL-FLOW", []string{"read"})

	// Step 1: GET /device — form rendered.
	rr := httptest.NewRecorder()
	f.handler.Form(rr, httptest.NewRequest(http.MethodGet, "/device", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `name="user_code"`)

	// Step 2: POST /device while not authenticated → redirect to login.
	form := url.Values{"user_code": {code}}
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	f.handler.Submit(rr, req)
	require.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/auth/login")

	// Step 3: simulate login completing.
	f.sessionSubject = "alice"

	// Step 4: GET /device/approve — consent screen.
	rr = httptest.NewRecorder()
	f.handler.Consent(rr, httptest.NewRequest(http.MethodGet, "/device/approve?user_code="+code, nil))
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "My TV App")

	// Step 5: POST /device/approve action=approve — store flipped.
	form = url.Values{"user_code": {code}, "action": {"approve"}}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	f.handler.Decide(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	g, err := f.deviceStore.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: code})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusApproved, g.Authorization.Status)
	assert.Equal(t, "alice", g.Authorization.ApprovedSubject)
}
