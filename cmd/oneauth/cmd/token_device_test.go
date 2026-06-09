package cmd

// End-to-end tests for `oneauth token device <issuer>` against a
// synthetic AS that serves /.well-known/oauth-authorization-server +
// /device/authorize + the device_code branch of /token.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type syntheticDeviceAS struct {
	srv          *httptest.Server
	deviceCalls  atomic.Int32
	tokenCalls   atomic.Int32
	tokenForm    chan map[string][]string
	tokenStrategy func(call int32, form map[string][]string) (status int, body any)
}

func newSyntheticDeviceAS(t *testing.T) *syntheticDeviceAS {
	t.Helper()
	as := &syntheticDeviceAS{
		tokenForm: make(chan map[string][]string, 8),
	}
	as.tokenStrategy = func(call int32, _ map[string][]string) (int, any) {
		// Default: first poll pending, second poll succeeds.
		if call == 1 {
			return http.StatusBadRequest, map[string]string{"error": "authorization_pending"}
		}
		return http.StatusOK, map[string]any{
			"access_token":  "AT-device-1",
			"refresh_token": "RT-device-1",
			"token_type":    "Bearer",
			"expires_in":    1800,
			"scope":         "read",
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                        as.srv.URL,
			"token_endpoint":                as.srv.URL + "/token",
			"device_authorization_endpoint": as.srv.URL + "/device/authorize",
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		})
	})
	mux.HandleFunc("/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		as.deviceCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dc-fixture",
			"user_code":                 "WDJB-MJHT",
			"verification_uri":          as.srv.URL + "/device",
			"verification_uri_complete": as.srv.URL + "/device?user_code=WDJB-MJHT",
			"expires_in":                900,
			"interval":                  1, // small for tests
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		select {
		case as.tokenForm <- r.Form:
		default:
		}
		call := as.tokenCalls.Add(1)
		status, body := as.tokenStrategy(call, r.Form)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

// silenceDeviceSleep replaces the polling sleep with a no-op for the
// duration of a test. Returns the restore function.
func silenceDeviceSleep(t *testing.T) func() {
	t.Helper()
	orig := devicePollSleep
	devicePollSleep = func(time.Duration) {}
	return func() { devicePollSleep = orig }
}

// recordOpenBrowser swaps the URL-opener for a fake that records the
// last URL it received. Returns a pointer the test can inspect plus the
// restore function.
func recordOpenBrowser(t *testing.T) (*string, func()) {
	t.Helper()
	var last string
	orig := deviceOpenBrowser
	deviceOpenBrowser = func(url string) error { last = url; return nil }
	return &last, func() { deviceOpenBrowser = orig }
}

// recordWriteQR swaps the QR renderer for a fake that records the URL
// and writes a sentinel string so the test can assert "QR was rendered."
func recordWriteQR(t *testing.T) (*string, func()) {
	t.Helper()
	var last string
	orig := deviceWriteQR
	deviceWriteQR = func(w io.Writer, url string) {
		last = url
		_, _ = w.Write([]byte("QR{" + url + "}"))
	}
	return &last, func() { deviceWriteQR = orig }
}

func TestRunDevice_HappyPath(t *testing.T) {
	defer silenceDeviceSleep(t)()
	as := newSyntheticDeviceAS(t)
	tf := &tokenFlags{format: "json"}
	df := &deviceFlags{
		clientID: "demo",
		timeout:  30 * time.Second,
	}
	var stdout, stderr bytes.Buffer
	require.NoError(t, runDevice(context.Background(), &stdout, &stderr, as.srv.URL, tf, df))

	var out tokenOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, "AT-device-1", out.AccessToken)
	assert.Equal(t, "RT-device-1", out.RefreshToken)
	assert.Equal(t, "Bearer", out.TokenType)

	errOut := stderr.String()
	assert.Contains(t, errOut, "WDJB-MJHT", "stderr must surface the user_code")
	assert.Contains(t, errOut, "Waiting for authorization")
	assert.Equal(t, int32(2), as.tokenCalls.Load(), "expected pending → success poll sequence")
}

func TestRunDevice_AccessDenied(t *testing.T) {
	defer silenceDeviceSleep(t)()
	as := newSyntheticDeviceAS(t)
	as.tokenStrategy = func(int32, map[string][]string) (int, any) {
		return http.StatusBadRequest, map[string]string{"error": "access_denied"}
	}
	df := &deviceFlags{clientID: "demo", timeout: 30 * time.Second}
	err := runDevice(context.Background(), new(bytes.Buffer), new(bytes.Buffer), as.srv.URL, &tokenFlags{format: "json"}, df)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user denied")
}

func TestRunDevice_ExpiredToken(t *testing.T) {
	defer silenceDeviceSleep(t)()
	as := newSyntheticDeviceAS(t)
	as.tokenStrategy = func(int32, map[string][]string) (int, any) {
		return http.StatusBadRequest, map[string]string{"error": "expired_token"}
	}
	df := &deviceFlags{clientID: "demo", timeout: 30 * time.Second}
	err := runDevice(context.Background(), new(bytes.Buffer), new(bytes.Buffer), as.srv.URL, &tokenFlags{format: "json"}, df)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestRunDevice_SlowDownBumpsInterval(t *testing.T) {
	defer silenceDeviceSleep(t)()
	as := newSyntheticDeviceAS(t)
	as.tokenStrategy = func(call int32, _ map[string][]string) (int, any) {
		switch call {
		case 1:
			return http.StatusBadRequest, map[string]string{"error": "slow_down"}
		default:
			return http.StatusOK, map[string]any{
				"access_token": "AT-slowed",
				"token_type":   "Bearer",
				"expires_in":   1800,
			}
		}
	}
	df := &deviceFlags{clientID: "demo", timeout: 30 * time.Second}
	var stderr bytes.Buffer
	require.NoError(t, runDevice(context.Background(), new(bytes.Buffer), &stderr, as.srv.URL, &tokenFlags{format: "json"}, df))
	assert.Contains(t, stderr.String(), "slow_down",
		"stderr should surface the slow_down notification")
}

func TestRunDevice_OpenBrowserCalled(t *testing.T) {
	defer silenceDeviceSleep(t)()
	openedURL, restoreOpen := recordOpenBrowser(t)
	defer restoreOpen()

	as := newSyntheticDeviceAS(t)
	df := &deviceFlags{
		clientID:    "demo",
		timeout:     30 * time.Second,
		openBrowser: true,
	}
	var stderr bytes.Buffer
	require.NoError(t, runDevice(context.Background(), new(bytes.Buffer), &stderr, as.srv.URL, &tokenFlags{format: "json"}, df))
	require.NotEmpty(t, *openedURL, "--open MUST trigger the browser opener")
	assert.Contains(t, *openedURL, "user_code=WDJB-MJHT",
		"opener should prefer verification_uri_complete when advertised")
}

func TestRunDevice_OpenBrowserNotCalledByDefault(t *testing.T) {
	defer silenceDeviceSleep(t)()
	openedURL, restoreOpen := recordOpenBrowser(t)
	defer restoreOpen()

	as := newSyntheticDeviceAS(t)
	df := &deviceFlags{clientID: "demo", timeout: 30 * time.Second}
	require.NoError(t, runDevice(context.Background(), new(bytes.Buffer), new(bytes.Buffer), as.srv.URL, &tokenFlags{format: "json"}, df))
	assert.Empty(t, *openedURL, "--open omitted → browser opener MUST NOT be called")
}

func TestRunDevice_QRRendered(t *testing.T) {
	defer silenceDeviceSleep(t)()
	qrURL, restoreQR := recordWriteQR(t)
	defer restoreQR()

	as := newSyntheticDeviceAS(t)
	df := &deviceFlags{clientID: "demo", timeout: 30 * time.Second, showQR: true}
	var stderr bytes.Buffer
	require.NoError(t, runDevice(context.Background(), new(bytes.Buffer), &stderr, as.srv.URL, &tokenFlags{format: "json"}, df))
	assert.Contains(t, stderr.String(), "QR{")
	assert.Contains(t, *qrURL, "user_code=WDJB-MJHT")
}

func TestRunDevice_QRNotRenderedByDefault(t *testing.T) {
	defer silenceDeviceSleep(t)()
	qrURL, restoreQR := recordWriteQR(t)
	defer restoreQR()

	as := newSyntheticDeviceAS(t)
	df := &deviceFlags{clientID: "demo", timeout: 30 * time.Second}
	var stderr bytes.Buffer
	require.NoError(t, runDevice(context.Background(), new(bytes.Buffer), &stderr, as.srv.URL, &tokenFlags{format: "json"}, df))
	assert.NotContains(t, stderr.String(), "QR{")
	assert.Empty(t, *qrURL)
}

func TestRunDevice_NoDeviceEndpointAdvertised(t *testing.T) {
	// AS without device_authorization_endpoint → fail loudly.
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         srv.URL,
			"token_endpoint": srv.URL + "/token",
			// no device_authorization_endpoint
		})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	defer silenceDeviceSleep(t)()
	df := &deviceFlags{clientID: "demo", timeout: 30 * time.Second}
	err := runDevice(context.Background(), new(bytes.Buffer), new(bytes.Buffer), srv.URL, &tokenFlags{format: "json"}, df)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "device_authorization_endpoint")
}

func TestRunDevice_Timeout(t *testing.T) {
	// Always-pending AS → caller's --timeout must fire.
	defer silenceDeviceSleep(t)()
	as := newSyntheticDeviceAS(t)
	as.tokenStrategy = func(int32, map[string][]string) (int, any) {
		return http.StatusBadRequest, map[string]string{"error": "authorization_pending"}
	}
	df := &deviceFlags{clientID: "demo", timeout: time.Millisecond}
	err := runDevice(context.Background(), new(bytes.Buffer), new(bytes.Buffer), as.srv.URL, &tokenFlags{format: "json"}, df)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}
