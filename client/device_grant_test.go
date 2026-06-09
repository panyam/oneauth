package client

// Tests for the RFC 8628 Device Authorization Grant client SDK methods
// (DeviceAuthorization + PollDeviceToken). Drives both methods against a
// synthetic AS that serves /device/authorize + the device_code token
// branch.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type deviceAS struct {
	srv        *httptest.Server
	pollCount  atomic.Int32
	deviceForm chan map[string][]string
	tokenForm  chan map[string][]string
	// Token endpoint response strategy. Default emits authorization_pending.
	tokenResponder func(form map[string][]string) (status int, body any)
}

func newDeviceAS(t *testing.T) *deviceAS {
	t.Helper()
	as := &deviceAS{
		deviceForm: make(chan map[string][]string, 4),
		tokenForm:  make(chan map[string][]string, 8),
	}
	as.tokenResponder = func(form map[string][]string) (int, any) {
		return http.StatusBadRequest, map[string]string{"error": "authorization_pending"}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		select {
		case as.deviceForm <- r.Form:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dc-test-123",
			"user_code":                 "WDJB-MJHT",
			"verification_uri":          as.srv.URL + "/device",
			"verification_uri_complete": as.srv.URL + "/device?user_code=WDJB-MJHT",
			"expires_in":                900,
			"interval":                  5,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		select {
		case as.tokenForm <- r.Form:
		default:
		}
		as.pollCount.Add(1)
		status, body := as.tokenResponder(r.Form)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func newDeviceClient(t *testing.T, as *deviceAS) *AuthClient {
	t.Helper()
	ac := NewAuthClient(as.srv.URL, nil,
		WithASMetadata(&ASMetadata{
			Issuer:                      as.srv.URL,
			TokenEndpoint:               as.srv.URL + "/token",
			DeviceAuthorizationEndpoint: as.srv.URL + "/device/authorize",
		}),
	)
	return ac
}

func TestDeviceAuthorization_HappyPath(t *testing.T) {
	as := newDeviceAS(t)
	ac := newDeviceClient(t, as)
	resp, err := ac.DeviceAuthorization(context.Background(), &DeviceAuthorizationRequest{
		ClientID: "demo",
		Scopes:   []string{"read", "write"},
	})
	require.NoError(t, err)
	assert.Equal(t, "dc-test-123", resp.DeviceCode)
	assert.Equal(t, "WDJB-MJHT", resp.UserCode)
	assert.Equal(t, as.srv.URL+"/device", resp.VerificationURI)
	assert.NotEmpty(t, resp.VerificationURIComplete)
	assert.Equal(t, int64(900), resp.ExpiresIn)
	assert.Equal(t, 5, resp.Interval)

	form := <-as.deviceForm
	assert.Equal(t, []string{"demo"}, form["client_id"])
	assert.Equal(t, []string{"read write"}, form["scope"])
}

func TestDeviceAuthorization_NoEndpointAdvertised(t *testing.T) {
	ac := NewAuthClient("https://nope.example", nil,
		WithASMetadata(&ASMetadata{
			Issuer:        "https://nope.example",
			TokenEndpoint: "https://nope.example/token",
			// no DeviceAuthorizationEndpoint
		}),
	)
	_, err := ac.DeviceAuthorization(context.Background(), &DeviceAuthorizationRequest{ClientID: "demo"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device_authorization_endpoint")
}

func TestPollDeviceToken_AuthorizationPending(t *testing.T) {
	as := newDeviceAS(t)
	ac := newDeviceClient(t, as)
	_, err := ac.PollDeviceToken(context.Background(), &PollDeviceTokenRequest{
		DeviceCode: "dc",
		ClientID:   "demo",
	})
	require.True(t, errors.Is(err, ErrAuthorizationPending), "expected sentinel, got: %v", err)

	form := <-as.tokenForm
	assert.Equal(t, []string{DeviceCodeGrantType}, form["grant_type"])
	assert.Equal(t, []string{"dc"}, form["device_code"])
	assert.Equal(t, []string{"demo"}, form["client_id"])
}

func TestPollDeviceToken_SlowDown(t *testing.T) {
	as := newDeviceAS(t)
	as.tokenResponder = func(map[string][]string) (int, any) {
		return http.StatusBadRequest, map[string]string{"error": "slow_down"}
	}
	ac := newDeviceClient(t, as)
	_, err := ac.PollDeviceToken(context.Background(), &PollDeviceTokenRequest{DeviceCode: "dc", ClientID: "demo"})
	require.True(t, errors.Is(err, ErrSlowDown))
}

func TestPollDeviceToken_AccessDenied(t *testing.T) {
	as := newDeviceAS(t)
	as.tokenResponder = func(map[string][]string) (int, any) {
		return http.StatusBadRequest, map[string]string{"error": "access_denied"}
	}
	ac := newDeviceClient(t, as)
	_, err := ac.PollDeviceToken(context.Background(), &PollDeviceTokenRequest{DeviceCode: "dc", ClientID: "demo"})
	require.True(t, errors.Is(err, ErrAccessDenied))
}

func TestPollDeviceToken_ExpiredToken(t *testing.T) {
	as := newDeviceAS(t)
	as.tokenResponder = func(map[string][]string) (int, any) {
		return http.StatusBadRequest, map[string]string{"error": "expired_token"}
	}
	ac := newDeviceClient(t, as)
	_, err := ac.PollDeviceToken(context.Background(), &PollDeviceTokenRequest{DeviceCode: "dc", ClientID: "demo"})
	require.True(t, errors.Is(err, ErrExpiredToken))
}

func TestPollDeviceToken_InvalidGrant_NotSentinel(t *testing.T) {
	// Non-§3.5 errors must surface as generic error, NOT be mistaken for
	// a sentinel (else a misbehaving AS could trap callers in a poll loop).
	as := newDeviceAS(t)
	as.tokenResponder = func(map[string][]string) (int, any) {
		return http.StatusBadRequest, map[string]string{"error": "invalid_grant"}
	}
	ac := newDeviceClient(t, as)
	_, err := ac.PollDeviceToken(context.Background(), &PollDeviceTokenRequest{DeviceCode: "dc", ClientID: "demo"})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrAuthorizationPending))
	assert.False(t, errors.Is(err, ErrSlowDown))
	assert.False(t, errors.Is(err, ErrAccessDenied))
	assert.False(t, errors.Is(err, ErrExpiredToken))
	assert.Contains(t, err.Error(), "invalid_grant")
}

func TestPollDeviceToken_Success(t *testing.T) {
	as := newDeviceAS(t)
	as.tokenResponder = func(form map[string][]string) (int, any) {
		// Confidential clients send client_secret in the form.
		assert.Equal(t, []string{"confidential-secret"}, form["client_secret"])
		return http.StatusOK, map[string]any{
			"access_token":  "AT-test",
			"refresh_token": "RT-test",
			"token_type":    "Bearer",
			"expires_in":    1800,
			"scope":         "read write",
		}
	}
	ac := newDeviceClient(t, as)
	cred, err := ac.PollDeviceToken(context.Background(), &PollDeviceTokenRequest{
		DeviceCode:   "dc",
		ClientID:     "demo",
		ClientSecret: "confidential-secret",
	})
	require.NoError(t, err)
	assert.Equal(t, "AT-test", cred.AccessToken)
	assert.Equal(t, "RT-test", cred.RefreshToken)
	assert.Equal(t, "Bearer", cred.TokenType)
	assert.Equal(t, "read write", cred.Scope)
	assert.True(t, cred.ExpiresAt.After(cred.ExpiresAt.Add(-2000*1e9)),
		"ExpiresAt should be set from expires_in")
}

func TestDeviceAuthorization_ConfidentialClient_SecretInForm(t *testing.T) {
	as := newDeviceAS(t)
	ac := newDeviceClient(t, as)
	_, err := ac.DeviceAuthorization(context.Background(), &DeviceAuthorizationRequest{
		ClientID:     "confidential-demo",
		ClientSecret: "shh",
	})
	require.NoError(t, err)
	form := <-as.deviceForm
	assert.Equal(t, []string{"confidential-demo"}, form["client_id"])
	assert.Equal(t, []string{"shh"}, form["client_secret"])
}

func TestDeviceAuthorization_AudiencePassedThrough(t *testing.T) {
	as := newDeviceAS(t)
	ac := newDeviceClient(t, as)
	_, err := ac.DeviceAuthorization(context.Background(), &DeviceAuthorizationRequest{
		ClientID: "demo",
		Audience: "https://api.example/v1",
	})
	require.NoError(t, err)
	form := <-as.deviceForm
	assert.Equal(t, []string{"https://api.example/v1"}, form["audience"])
}

// Avoid unused-import warnings when the test file shrinks during edits.
var _ = strings.Builder{}
