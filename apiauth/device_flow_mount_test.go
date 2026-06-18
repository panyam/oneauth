package apiauth_test

// Tests for apiauth.MountDeviceFlow — the helper that stamps the five
// RFC 8628 routes onto an http.ServeMux. Behavioral coverage of the
// device-grant arc itself lives in tests/e2e/device_flow_test.go (issue
// 276); this file pins the helper's pre-conditions and route layout.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func defaultMountCfg() apiauth.DeviceFlowMountConfig {
	return apiauth.DeviceFlowMountConfig{
		OneAuth: apiauth.NewOneAuth(apiauth.OneAuthConfig{
			KeyStore:        nil,
			DeviceAuthStore: core.NewInMemoryDeviceAuthorizationStore(),
		}),
		VerificationURI:      "https://auth.example/device",
		SubjectFromRequest:   func(r *http.Request) string { return "" },
		CSRFTokenFromRequest: func(r *http.Request) string { return "test-csrf" },
	}
}

// TestMountDeviceFlow_PanicsOnMissingAPIAuth pins that a missing
// APIAuth is rejected loudly at mount time. Required because nil
// dereference at request time would surface a 500 with a stack trace,
// not a usable diagnostic.
func TestMountDeviceFlow_PanicsOnMissingAPIAuth(t *testing.T) {
	cfg := defaultMountCfg()
	cfg.OneAuth = nil
	assert.PanicsWithValue(t, "apiauth: MountDeviceFlow: cfg.OneAuth is required", func() {
		apiauth.MountDeviceFlow(http.NewServeMux(), cfg)
	})
}

// TestMountDeviceFlow_PanicsOnMissingDeviceAuthStore pins that a
// populated APIAuth with no DeviceAuthStore is rejected — every
// /device/authorize call and every consent-UI lookup needs persistence
// per RFC 8628.
func TestMountDeviceFlow_PanicsOnMissingDeviceAuthStore(t *testing.T) {
	cfg := defaultMountCfg()
	cfg.OneAuth.DeviceAuthStore = nil
	assert.PanicsWithValue(t, "apiauth: MountDeviceFlow: cfg.OneAuth.DeviceAuthStore is required (RFC 8628 needs persistence)", func() {
		apiauth.MountDeviceFlow(http.NewServeMux(), cfg)
	})
}

// TestMountDeviceFlow_PanicsOnMissingVerificationURI pins that the
// RFC 8628 §3.2 required field is enforced. Empty would yield a
// response with verification_uri="", which is a wire-format bug
// disguised as a 200.
func TestMountDeviceFlow_PanicsOnMissingVerificationURI(t *testing.T) {
	cfg := defaultMountCfg()
	cfg.VerificationURI = ""
	assert.PanicsWithValue(t, "apiauth: MountDeviceFlow: cfg.VerificationURI is required (RFC 8628 §3.2)", func() {
		apiauth.MountDeviceFlow(http.NewServeMux(), cfg)
	})
}

// TestMountDeviceFlow_RegistersFiveRoutes pins the canonical route
// layout. Hitting each route returns a non-404 — sufficient to prove
// the handler is mounted; behavior is covered elsewhere.
func TestMountDeviceFlow_RegistersFiveRoutes(t *testing.T) {
	mux := http.NewServeMux()
	apiauth.MountDeviceFlow(mux, defaultMountCfg())

	cases := []struct {
		method, path string
	}{
		{http.MethodPost, "/device/authorize"},
		{http.MethodGet, "/device"},
		{http.MethodPost, "/device"},
		{http.MethodGet, "/device/approve"},
		{http.MethodPost, "/device/approve"},
	}
	for _, tc := range cases {
		t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(""))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			assert.NotEqual(t, http.StatusNotFound, rr.Code,
				"%s %s MUST be registered by MountDeviceFlow", tc.method, tc.path)
		})
	}
}

// TestMountDeviceFlow_VerifierMiddlewareWrapsBrowserRoutesNotAuthorize
// pins the deliberate asymmetry: the /device/authorize machine endpoint
// is NOT wrapped by VerifierMiddleware (CSRF does not apply to a
// device-driven JSON request), while the four browser-facing routes
// ARE. A test middleware tags every wrapped response so we can read
// which routes ran through it.
func TestMountDeviceFlow_VerifierMiddlewareWrapsBrowserRoutesNotAuthorize(t *testing.T) {
	cfg := defaultMountCfg()
	cfg.VerifierMiddleware = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Wrapped", "yes")
			next.ServeHTTP(w, r)
		})
	}
	mux := http.NewServeMux()
	apiauth.MountDeviceFlow(mux, cfg)

	// /device/authorize is the machine endpoint — must NOT be wrapped.
	form := url.Values{"client_id": {"client-x"}}
	req := httptest.NewRequest(http.MethodPost, "/device/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Empty(t, rr.Header().Get("X-Wrapped"),
		"/device/authorize is a machine endpoint and MUST NOT be wrapped with the browser middleware")

	// All four verifier routes MUST be wrapped.
	browserRoutes := []struct{ method, path string }{
		{http.MethodGet, "/device"},
		{http.MethodPost, "/device"},
		{http.MethodGet, "/device/approve"},
		{http.MethodPost, "/device/approve"},
	}
	for _, route := range browserRoutes {
		t.Run(route.method+"_"+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, strings.NewReader(""))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			assert.Equal(t, "yes", rr.Header().Get("X-Wrapped"),
				"%s %s MUST run through VerifierMiddleware", route.method, route.path)
		})
	}
}

// TestMountDeviceFlow_VerificationURIEchoedToDevice pins that the
// configured VerificationURI flows through to the
// DeviceAuthorizationHandler — a wire-format regression would surface
// as a different URL on the response payload.
func TestMountDeviceFlow_VerificationURIEchoedToDevice(t *testing.T) {
	cfg := defaultMountCfg()
	cfg.VerificationURI = "https://canary.example/device"
	mux := http.NewServeMux()
	apiauth.MountDeviceFlow(mux, cfg)

	form := url.Values{"client_id": {"client-x"}}
	req := httptest.NewRequest(http.MethodPost, "/device/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "https://canary.example/device",
		"configured VerificationURI MUST appear on the /device/authorize response")
}
