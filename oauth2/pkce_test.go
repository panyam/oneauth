package oauth2_test

// Tests for PKCE (Proof Key for Code Exchange, RFC 7636) implementation.
// PKCE prevents authorization code interception attacks where a malicious app
// on the same device intercepts the OAuth redirect and steals the auth code.
//
// References:
//   - RFC 7636 (https://datatracker.ietf.org/doc/html/rfc7636):
//     Proof Key for Code Exchange by OAuth Public Clients
//   - OAuth 2.1 draft: PKCE is REQUIRED for all clients (not just public)
//   - CWE-352 applied to OAuth: authorization code interception

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/oauth2"
	oauth2lib "golang.org/x/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// PKCE Utility Tests (pass immediately — new functions)
// =============================================================================

// TestPKCE_GenerateVerifier_Length verifies that the code verifier is the
// correct length per RFC 7636 §4.1 (43-128 unreserved characters).
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
func TestPKCE_GenerateVerifier_Length(t *testing.T) {
	verifier, err := oauth2.GenerateCodeVerifier()
	require.NoError(t, err)

	// 32 bytes → 43 base64url characters (no padding)
	assert.Len(t, verifier, 43, "code verifier should be 43 characters")

	// Must be base64url-safe characters only
	for _, c := range verifier {
		assert.True(t,
			(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_',
			"verifier contains non-base64url character: %c", c)
	}
}

// TestPKCE_GenerateVerifier_Unique verifies that successive verifiers
// are cryptographically distinct (no reuse of random state).
func TestPKCE_GenerateVerifier_Unique(t *testing.T) {
	v1, _ := oauth2.GenerateCodeVerifier()
	v2, _ := oauth2.GenerateCodeVerifier()
	assert.NotEqual(t, v1, v2, "two verifiers should never be identical")
}

// TestPKCE_ChallengeMatchesVerifier verifies that ComputeCodeChallenge
// produces the correct S256 challenge: BASE64URL(SHA256(verifier)).
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
func TestPKCE_ChallengeMatchesVerifier(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := oauth2.ComputeCodeChallenge(verifier)

	// Manually compute expected challenge
	hash := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	assert.Equal(t, expected, challenge)
}

// TestPKCE_VerifierCookieHttpOnly verifies that the PKCE cookie is HttpOnly
// so JavaScript cannot read the code verifier (XSS protection).
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-7.1
func TestPKCE_VerifierCookieHttpOnly(t *testing.T) {
	rr := httptest.NewRecorder()
	oauth2.SetPKCECookie(rr, "test-verifier", false)

	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, oauth2.PKCECookieName, cookie.Name)
	assert.Equal(t, "test-verifier", cookie.Value)
	assert.True(t, cookie.HttpOnly, "PKCE cookie must be HttpOnly")
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
}

// =============================================================================
// PKCE Flow Tests (FAIL before fix — providers don't send PKCE params yet)
// =============================================================================

// TestPKCE_AuthURLContainsChallenge verifies that the authorization redirect
// includes code_challenge and code_challenge_method=S256 parameters.
// Without these, the OAuth provider can't enforce PKCE.
//
// BEFORE FIX: auth URL has no code_challenge parameter
// AFTER FIX: auth URL includes code_challenge=... and code_challenge_method=S256
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func TestPKCE_AuthURLContainsChallenge(t *testing.T) {
	mock := newMockOAuthServer()
	defer mock.server.Close()

	provider := oauth2.NewGoogleOAuth2("client-id", "client-secret",
		mock.server.URL+"/callback/", nil)
	provider.SetOAuthEndpoint(oauth2lib.Endpoint{
		AuthURL:  mock.server.URL + "/authorize",
		TokenURL: mock.server.URL + "/token",
	})

	// Request the authorization redirect
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	provider.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code, "should redirect to OAuth provider")

	// Parse the redirect URL
	location := rr.Header().Get("Location")
	require.NotEmpty(t, location)
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)

	// Verify PKCE parameters are present
	assert.NotEmpty(t, redirectURL.Query().Get("code_challenge"),
		"auth URL must include code_challenge parameter")
	assert.Equal(t, "S256", redirectURL.Query().Get("code_challenge_method"),
		"auth URL must use S256 challenge method")
}

// TestPKCE_AuthURLSetsPKCECookie verifies that the authorization redirect
// sets an HttpOnly cookie containing the code verifier.
//
// BEFORE FIX: no PKCE cookie set
// AFTER FIX: pkce_verifier cookie set with HttpOnly flag
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
func TestPKCE_AuthURLSetsPKCECookie(t *testing.T) {
	mock := newMockOAuthServer()
	defer mock.server.Close()

	provider := oauth2.NewGoogleOAuth2("client-id", "client-secret",
		mock.server.URL+"/callback/", nil)
	provider.SetOAuthEndpoint(oauth2lib.Endpoint{
		AuthURL:  mock.server.URL + "/authorize",
		TokenURL: mock.server.URL + "/token",
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	provider.Handler().ServeHTTP(rr, req)

	// Find the PKCE cookie
	var pkceCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == oauth2.PKCECookieName {
			pkceCookie = c
			break
		}
	}
	require.NotNil(t, pkceCookie, "PKCE verifier cookie must be set on auth redirect")
	assert.True(t, pkceCookie.HttpOnly, "PKCE cookie must be HttpOnly")
	assert.NotEmpty(t, pkceCookie.Value, "PKCE cookie value must not be empty")
}

// TestPKCE_CallbackSendsVerifier verifies that the callback handler sends
// the code_verifier to the token endpoint during code exchange.
// Without this, the OAuth provider will reject the exchange even though
// a code_challenge was sent in the authorization request.
//
// BEFORE FIX: token exchange has no code_verifier
// AFTER FIX: token exchange includes code_verifier parameter
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
func TestPKCE_CallbackSendsVerifier(t *testing.T) {
	var receivedVerifier string

	// Mock OAuth server that captures the code_verifier from token exchange
	mock := newMockOAuthServer()
	mock.server.Close() // close the default one, we need a custom token handler

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedVerifier = r.FormValue("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock_token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"email": "test@example.com",
			"name":  "Test User",
		})
	})
	mockServer := httptest.NewServer(mux)
	defer mockServer.Close()

	provider := oauth2.NewGoogleOAuth2("client-id", "client-secret",
		mockServer.URL+"/callback/", func(authtype, prov string, token *oauth2lib.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	provider.SetOAuthEndpoint(oauth2lib.Endpoint{
		AuthURL:  mockServer.URL + "/authorize",
		TokenURL: mockServer.URL + "/token",
	})
	provider.UserInfoURL = mockServer.URL + "/userinfo"
	provider.SetHTTPClient(mockServer.Client())

	// Simulate the callback with a valid state cookie and PKCE verifier cookie
	verifier, _ := oauth2.GenerateCodeVerifier()

	req := httptest.NewRequest("GET", "/callback/?code=test-auth-code&state=test-state", nil)
	req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "test-state"})
	req.AddCookie(&http.Cookie{Name: oauth2.PKCECookieName, Value: verifier})
	rr := httptest.NewRecorder()
	provider.Handler().ServeHTTP(rr, req)

	assert.NotEmpty(t, receivedVerifier,
		"token exchange must include code_verifier parameter")
	assert.Equal(t, verifier, receivedVerifier,
		"code_verifier sent to token endpoint must match the stored verifier")
}

// TestPKCE_MissingVerifierRejectsCallback verifies that if the PKCE verifier
// cookie is missing during callback (e.g., cookie expired or was stripped),
// the callback fails gracefully rather than proceeding without PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
func TestPKCE_MissingVerifierRejectsCallback(t *testing.T) {
	mock := newMockOAuthServer()
	defer mock.server.Close()

	provider := oauth2.NewGoogleOAuth2("client-id", "client-secret",
		mock.server.URL+"/callback/", func(authtype, prov string, token *oauth2lib.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			t.Error("HandleUser should not be called when PKCE verifier is missing")
		})
	provider.SetOAuthEndpoint(oauth2lib.Endpoint{
		AuthURL:  mock.server.URL + "/authorize",
		TokenURL: mock.server.URL + "/token",
	})
	provider.SetHTTPClient(mock.server.Client())

	// Callback WITHOUT PKCE verifier cookie — should be rejected
	req := httptest.NewRequest("GET", "/callback/?code=test-auth-code&state=test-state", nil)
	req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "test-state"})
	// No PKCE cookie!
	rr := httptest.NewRecorder()
	provider.Handler().ServeHTTP(rr, req)

	assert.True(t, rr.Code >= 400 || strings.Contains(rr.Header().Get("Location"), "failed"),
		"missing PKCE verifier should reject the callback (got %d)", rr.Code)
}
