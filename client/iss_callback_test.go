package client

// Tests for the RFC 9207 iss surfacing on the loopback redirect callback (#235).
// The hook on BrowserLoginRequest fires between state validation and the
// token exchange so consumers can apply their own iss policy.
//
// See: https://www.rfc-editor.org/rfc/rfc9207

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuthServerWithIss is a variant of mockAuthServer that includes (or
// omits, when includeIss=false) the RFC 9207 iss query parameter on the
// success redirect. issValue is the issuer URL the AS claims for itself.
func mockAuthServerWithIss(t *testing.T, includeIss bool, issValue string) *httptest.Server {
	t.Helper()
	var storedChallenge, storedState, storedRedirectURI string

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		storedChallenge = q.Get("code_challenge")
		storedState = q.Get("state")
		storedRedirectURI = q.Get("redirect_uri")

		redirectURL := fmt.Sprintf("%s?code=test-auth-code&state=%s", storedRedirectURI, storedState)
		if includeIss {
			redirectURL += "&iss=" + issValue
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		verifier := r.FormValue("code_verifier")
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		if computed != storedChallenge {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   900,
		})
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		srv := r.Host
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           "http://" + srv,
			"authorization_endpoint":           "http://" + srv + "/authorize",
			"token_endpoint":                   "http://" + srv + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestLoginWithBrowser_IssPassedToCallback asserts that the iss query
// parameter sent on the authorization-response redirect lands in the
// OnCallback hook with the exact value the AS sent.
func TestLoginWithBrowser_IssPassedToCallback(t *testing.T) {
	const wantIss = "http://issuer.example.test"
	authSrv := mockAuthServerWithIss(t, true, wantIss)
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	var gotParams CallbackParams
	var hookFired bool
	_, err := authClient.LoginWithBrowser(context.Background(), &BrowserLoginRequest{
		ClientID: "test-cli",
		Scopes:   []string{"openid"},
		Timeout:  5 * time.Second,
		OpenBrowser: func(authURL string) error {
			go simulateBrowser(authURL)
			return nil
		},
		OnCallback: func(_ context.Context, params CallbackParams) error {
			hookFired = true
			gotParams = params
			return nil
		},
	})
	require.NoError(t, err)
	assert.True(t, hookFired, "OnCallback should have fired")
	assert.Equal(t, wantIss, gotParams.Iss, "iss query parameter must be passed through verbatim")
	assert.Equal(t, "test-auth-code", gotParams.Code)
	assert.NotEmpty(t, gotParams.State)
}

// TestLoginWithBrowser_NoIssQueryParam asserts that when the AS omits the
// iss parameter (legacy ASes pre-dating RFC 9207), the hook still fires
// with Iss=="" so consumer policy can decide whether absence is acceptable.
func TestLoginWithBrowser_NoIssQueryParam(t *testing.T) {
	authSrv := mockAuthServerWithIss(t, false, "")
	store := newMockCredentialStore()
	authClient := NewAuthClient(authSrv.URL, store)

	var gotParams CallbackParams
	var hookFired bool
	_, err := authClient.LoginWithBrowser(context.Background(), &BrowserLoginRequest{
		ClientID: "test-cli",
		Scopes:   []string{"openid"},
		Timeout:  5 * time.Second,
		OpenBrowser: func(authURL string) error {
			go simulateBrowser(authURL)
			return nil
		},
		OnCallback: func(_ context.Context, params CallbackParams) error {
			hookFired = true
			gotParams = params
			return nil
		},
	})
	require.NoError(t, err)
	assert.True(t, hookFired)
	assert.Empty(t, gotParams.Iss, "absent iss should surface as empty, not synthesized")
	assert.NotEmpty(t, gotParams.Code)
}

// TestLoginWithBrowser_CallbackHookErrorAbortsFlow asserts that returning
// a non-nil error from the hook aborts the flow with that error wrapped,
// and crucially that the token exchange never fires (verified by a server
// that would fail the request if /token were hit).
func TestLoginWithBrowser_CallbackHookErrorAbortsFlow(t *testing.T) {
	var tokenCalled bool
	mux := http.NewServeMux()
	var storedState, storedRedirectURI string
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		storedState = q.Get("state")
		storedRedirectURI = q.Get("redirect_uri")
		http.Redirect(w, r,
			fmt.Sprintf("%s?code=x&state=%s&iss=http://evil.example", storedRedirectURI, storedState),
			http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalled = true
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           "http://" + r.Host,
			"authorization_endpoint":           "http://" + r.Host + "/authorize",
			"token_endpoint":                   "http://" + r.Host + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rejectErr := errors.New("iss mismatch")
	authClient := NewAuthClient(srv.URL, newMockCredentialStore())
	_, err := authClient.LoginWithBrowser(context.Background(), &BrowserLoginRequest{
		ClientID: "test-cli",
		Scopes:   []string{"openid"},
		Timeout:  5 * time.Second,
		OpenBrowser: func(authURL string) error {
			go simulateBrowser(authURL)
			return nil
		},
		OnCallback: func(_ context.Context, params CallbackParams) error {
			return rejectErr
		},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, rejectErr, "hook error must be wrapped, not swallowed")
	assert.False(t, tokenCalled, "token exchange must NOT happen when hook rejects")
}
