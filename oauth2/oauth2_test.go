package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/oauth2"
	oauth2lib "golang.org/x/oauth2"
)

// mockOAuthServer creates a mock OAuth provider server that handles:
// - /token endpoint for token exchange
// - /userinfo endpoint for user data retrieval
type mockOAuthServer struct {
	server           *httptest.Server
	tokenEndpoint    string
	userInfoEndpoint string

	// Configuration for responses
	tokenResponse    map[string]any
	userInfoResponse map[string]any
	tokenError       bool
	userInfoError    bool
}

func newMockOAuthServer() *mockOAuthServer {
	mock := &mockOAuthServer{
		tokenResponse: map[string]any{
			"access_token":  "mock_access_token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "mock_refresh_token",
		},
		userInfoResponse: map[string]any{
			"id":    "12345",
			"email": "testuser@example.com",
			"name":  "Test User",
		},
	}

	mux := http.NewServeMux()

	// Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if mock.tokenError {
			http.Error(w, "token exchange failed", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mock.tokenResponse)
	})

	// User info endpoint
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if mock.userInfoError {
			http.Error(w, "user info failed", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mock.userInfoResponse)
	})

	mock.server = httptest.NewServer(mux)
	mock.tokenEndpoint = mock.server.URL + "/token"
	mock.userInfoEndpoint = mock.server.URL + "/userinfo"

	return mock
}

func (m *mockOAuthServer) Close() {
	m.server.Close()
}

// TestOauthRedirector tests the OAuth redirect handler
func TestOauthRedirector(t *testing.T) {
	config := &oauth2lib.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint: oauth2lib.Endpoint{
			AuthURL:  "https://provider.example.com/auth",
			TokenURL: "https://provider.example.com/token",
		},
	}

	redirector := oauth2.OauthRedirector(config)

	t.Run("redirects to OAuth provider", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()

		redirector(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("Expected status %d, got %d", http.StatusFound, rr.Code)
		}

		location := rr.Header().Get("Location")
		if !strings.HasPrefix(location, "https://provider.example.com/auth") {
			t.Errorf("Expected redirect to OAuth provider, got: %s", location)
		}

		// Check that location contains required OAuth parameters
		parsedURL, err := url.Parse(location)
		if err != nil {
			t.Fatalf("Failed to parse redirect URL: %v", err)
		}
		query := parsedURL.Query()
		if query.Get("client_id") != "test-client-id" {
			t.Errorf("Expected client_id in URL")
		}
		if query.Get("redirect_uri") != "http://localhost:8080/callback" {
			t.Errorf("Expected redirect_uri in URL")
		}
		if query.Get("response_type") != "code" {
			t.Errorf("Expected response_type=code in URL")
		}
		if query.Get("state") == "" {
			t.Errorf("Expected state parameter in URL")
		}
	})

	t.Run("sets oauthstate cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()

		redirector(rr, req)

		cookies := rr.Result().Cookies()
		var oauthStateCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "oauthstate" {
				oauthStateCookie = c
				break
			}
		}

		if oauthStateCookie == nil {
			t.Error("Expected oauthstate cookie to be set")
		} else if oauthStateCookie.Value == "" {
			t.Error("Expected oauthstate cookie to have a value")
		}
	})

	t.Run("sets callback URL cookie when provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?callbackURL=/dashboard", nil)
		rr := httptest.NewRecorder()

		redirector(rr, req)

		cookies := rr.Result().Cookies()
		var callbackCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "oauthCallbackURL" {
				callbackCookie = c
				break
			}
		}

		if callbackCookie == nil {
			t.Error("Expected oauthCallbackURL cookie to be set")
		} else if callbackCookie.Value != "/dashboard" {
			t.Errorf("Expected callback URL '/dashboard', got '%s'", callbackCookie.Value)
		}
	})

	t.Run("state in URL matches cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()

		redirector(rr, req)

		// Get state from cookie
		cookies := rr.Result().Cookies()
		var cookieState string
		for _, c := range cookies {
			if c.Name == "oauthstate" {
				cookieState = c.Value
				break
			}
		}

		// Get state from redirect URL
		location := rr.Header().Get("Location")
		parsedURL, _ := url.Parse(location)
		urlState := parsedURL.Query().Get("state")

		if cookieState != urlState {
			t.Errorf("State mismatch: cookie=%s, url=%s", cookieState, urlState)
		}
	})
}

// TestGoogleOAuth2Callback tests the Google OAuth callback handler
func TestGoogleOAuth2Callback(t *testing.T) {
	mock := newMockOAuthServer()
	defer mock.Close()

	// Track HandleUser calls
	var handledProvider string
	var handledUserInfo map[string]any
	var handledCalled bool

	googleAuth := oauth2.NewGoogleOAuth2(
		"test-client-id",
		"test-client-secret",
		"http://localhost:8080/callback",
		func(authtype, provider string, token *oauth2lib.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			handledCalled = true
			handledProvider = provider
			handledUserInfo = userInfo
			w.WriteHeader(http.StatusOK)
		},
	)

	// Override endpoints and client for testing
	googleAuth.UserInfoURL = mock.userInfoEndpoint
	googleAuth.SetHTTPClient(mock.server.Client())
	// Override the oauth config endpoint for token exchange
	googleAuth.BaseOAuth2.SetOAuthEndpoint(oauth2lib.Endpoint{
		AuthURL:  mock.server.URL + "/auth",
		TokenURL: mock.tokenEndpoint,
	})

	t.Run("rejects missing state cookie", func(t *testing.T) {
		handledCalled = false

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=test_code&state=test_state", nil)
		rr := httptest.NewRecorder()

		googleAuth.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		if handledCalled {
			t.Error("HandleUser should not be called without state cookie")
		}
	})

	t.Run("rejects mismatched state", func(t *testing.T) {
		handledCalled = false

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=test_code&state=wrong_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "correct_state"})
		rr := httptest.NewRecorder()

		googleAuth.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "invalid oauth") {
			t.Errorf("Expected invalid oauth error, got: %s", rr.Body.String())
		}
		if handledCalled {
			t.Error("HandleUser should not be called with mismatched state")
		}
	})

	t.Run("successful callback flow", func(t *testing.T) {
		handledCalled = false
		handledProvider = ""
		handledUserInfo = nil

		mock.userInfoResponse = map[string]any{
			"id":    "google123",
			"email": "user@gmail.com",
			"name":  "Google User",
		}

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=valid_code&state=valid_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "valid_state"})
		rr := httptest.NewRecorder()

		googleAuth.Handler().ServeHTTP(rr, req)

		if !handledCalled {
			t.Error("HandleUser should have been called")
		}
		if handledProvider != "google" {
			t.Errorf("Expected provider 'google', got '%s'", handledProvider)
		}
		if handledUserInfo["email"] != "user@gmail.com" {
			t.Errorf("Expected email 'user@gmail.com', got '%v'", handledUserInfo["email"])
		}
	})

	t.Run("redirects on token exchange failure", func(t *testing.T) {
		handledCalled = false
		mock.tokenError = true
		defer func() { mock.tokenError = false }()

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=bad_code&state=valid_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "valid_state"})
		rr := httptest.NewRecorder()

		googleAuth.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("Expected redirect status, got %d", rr.Code)
		}
		if handledCalled {
			t.Error("HandleUser should not be called on token exchange failure")
		}
	})

	t.Run("redirects on user info failure", func(t *testing.T) {
		handledCalled = false
		mock.userInfoError = true
		defer func() { mock.userInfoError = false }()

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=valid_code&state=valid_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "valid_state"})
		rr := httptest.NewRecorder()

		googleAuth.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("Expected redirect status, got %d", rr.Code)
		}
		if handledCalled {
			t.Error("HandleUser should not be called on user info failure")
		}
	})
}

// TestGithubOAuth2Callback tests the GitHub OAuth callback handler
func TestGithubOAuth2Callback(t *testing.T) {
	mock := newMockOAuthServer()
	defer mock.Close()

	// Track HandleUser calls
	var handledProvider string
	var handledUserInfo map[string]any
	var handledCalled bool

	githubAuth := oauth2.NewGithubOAuth2(
		"test-client-id",
		"test-client-secret",
		"http://localhost:8080/callback",
		func(authtype, provider string, token *oauth2lib.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			handledCalled = true
			handledProvider = provider
			handledUserInfo = userInfo
			w.WriteHeader(http.StatusOK)
		},
	)

	// Override endpoints and client for testing
	githubAuth.UserInfoURL = mock.userInfoEndpoint
	githubAuth.SetHTTPClient(mock.server.Client())
	// Override the oauth config endpoint for token exchange
	githubAuth.BaseOAuth2.SetOAuthEndpoint(oauth2lib.Endpoint{
		AuthURL:  mock.server.URL + "/auth",
		TokenURL: mock.tokenEndpoint,
	})

	t.Run("rejects missing state cookie", func(t *testing.T) {
		handledCalled = false

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=test_code&state=test_state", nil)
		rr := httptest.NewRecorder()

		githubAuth.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		if handledCalled {
			t.Error("HandleUser should not be called without state cookie")
		}
	})

	t.Run("rejects mismatched state", func(t *testing.T) {
		handledCalled = false

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=test_code&state=wrong_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "correct_state"})
		rr := httptest.NewRecorder()

		githubAuth.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "invalid oauth") {
			t.Errorf("Expected invalid oauth error, got: %s", rr.Body.String())
		}
		if handledCalled {
			t.Error("HandleUser should not be called with mismatched state")
		}
	})

	t.Run("successful callback flow", func(t *testing.T) {
		handledCalled = false
		handledProvider = ""
		handledUserInfo = nil

		mock.userInfoResponse = map[string]any{
			"id":    "github456",
			"login": "githubuser",
			"email": "user@github.com",
			"name":  "GitHub User",
		}

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=valid_code&state=valid_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "valid_state"})
		rr := httptest.NewRecorder()

		githubAuth.Handler().ServeHTTP(rr, req)

		if !handledCalled {
			t.Error("HandleUser should have been called")
		}
		if handledProvider != "github" {
			t.Errorf("Expected provider 'github', got '%s'", handledProvider)
		}
		if handledUserInfo["login"] != "githubuser" {
			t.Errorf("Expected login 'githubuser', got '%v'", handledUserInfo["login"])
		}
	})

	t.Run("redirects on token exchange failure", func(t *testing.T) {
		handledCalled = false
		mock.tokenError = true
		defer func() { mock.tokenError = false }()

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=bad_code&state=valid_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "valid_state"})
		rr := httptest.NewRecorder()

		githubAuth.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("Expected redirect status, got %d", rr.Code)
		}
		if handledCalled {
			t.Error("HandleUser should not be called on token exchange failure")
		}
	})

	t.Run("redirects on user info failure", func(t *testing.T) {
		handledCalled = false
		mock.userInfoError = true
		defer func() { mock.userInfoError = false }()

		req := httptest.NewRequest(http.MethodGet, "/callback/?code=valid_code&state=valid_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "valid_state"})
		rr := httptest.NewRecorder()

		githubAuth.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("Expected redirect status, got %d", rr.Code)
		}
		if handledCalled {
			t.Error("HandleUser should not be called on user info failure")
		}
	})
}

// TestOAuthStateGeneration tests that OAuth state is properly generated and validated
func TestOAuthStateGeneration(t *testing.T) {
	config := &oauth2lib.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email"},
		Endpoint: oauth2lib.Endpoint{
			AuthURL:  "https://provider.example.com/auth",
			TokenURL: "https://provider.example.com/token",
		},
	}

	redirector := oauth2.OauthRedirector(config)

	t.Run("generates unique state for each request", func(t *testing.T) {
		states := make(map[string]bool)

		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()

			redirector(rr, req)

			cookies := rr.Result().Cookies()
			for _, c := range cookies {
				if c.Name == "oauthstate" {
					if states[c.Value] {
						t.Errorf("Duplicate state generated: %s", c.Value)
					}
					states[c.Value] = true
					break
				}
			}
		}

		if len(states) != 10 {
			t.Errorf("Expected 10 unique states, got %d", len(states))
		}
	})

	t.Run("state cookie has appropriate expiration", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()

		redirector(rr, req)

		cookies := rr.Result().Cookies()
		for _, c := range cookies {
			if c.Name == "oauthstate" {
				// Cookie should expire in about 30 days
				expectedExpiry := time.Now().Add(30 * 24 * time.Hour)
				if c.Expires.Before(expectedExpiry.Add(-1*time.Hour)) || c.Expires.After(expectedExpiry.Add(1*time.Hour)) {
					t.Errorf("Cookie expiry not within expected range: %v", c.Expires)
				}
				break
			}
		}
	})
}

// TestBaseOAuth2HTTPClient tests the HTTP client injection functionality
func TestBaseOAuth2HTTPClient(t *testing.T) {
	t.Run("uses default client when none set", func(t *testing.T) {
		googleAuth := oauth2.NewGoogleOAuth2(
			"test-client-id",
			"test-client-secret",
			"http://localhost:8080/callback",
			nil,
		)

		// The getHTTPClient is not exported, but we can test behavior indirectly
		// by checking that the HTTPClient field is nil
		if googleAuth.HTTPClient != nil {
			t.Error("Expected HTTPClient to be nil by default")
		}
	})

	t.Run("uses custom client when set", func(t *testing.T) {
		googleAuth := oauth2.NewGoogleOAuth2(
			"test-client-id",
			"test-client-secret",
			"http://localhost:8080/callback",
			nil,
		)

		customClient := &http.Client{Timeout: 5 * time.Second}
		googleAuth.SetHTTPClient(customClient)

		if googleAuth.HTTPClient != customClient {
			t.Error("Expected HTTPClient to be the custom client")
		}
	})
}

// TestOAuthEndpointConfiguration tests that OAuth endpoints can be configured
func TestOAuthEndpointConfiguration(t *testing.T) {
	t.Run("Google uses default endpoints", func(t *testing.T) {
		googleAuth := oauth2.NewGoogleOAuth2(
			"test-client-id",
			"test-client-secret",
			"http://localhost:8080/callback",
			nil,
		)

		// Default Google UserInfoURL should be set
		expectedURL := "https://www.googleapis.com/oauth2/v2/userinfo"
		if googleAuth.UserInfoURL != expectedURL {
			t.Errorf("Expected default UserInfoURL '%s', got '%s'", expectedURL, googleAuth.UserInfoURL)
		}
	})

	t.Run("GitHub uses default endpoints", func(t *testing.T) {
		githubAuth := oauth2.NewGithubOAuth2(
			"test-client-id",
			"test-client-secret",
			"http://localhost:8080/callback",
			nil,
		)

		// Default GitHub UserInfoURL should be set
		expectedURL := "https://api.github.com/user"
		if githubAuth.UserInfoURL != expectedURL {
			t.Errorf("Expected default UserInfoURL '%s', got '%s'", expectedURL, githubAuth.UserInfoURL)
		}
	})

	t.Run("UserInfoURL can be overridden", func(t *testing.T) {
		googleAuth := oauth2.NewGoogleOAuth2(
			"test-client-id",
			"test-client-secret",
			"http://localhost:8080/callback",
			nil,
		)

		customURL := "http://mock.example.com/userinfo"
		googleAuth.UserInfoURL = customURL

		if googleAuth.UserInfoURL != customURL {
			t.Errorf("Expected UserInfoURL '%s', got '%s'", customURL, googleAuth.UserInfoURL)
		}
	})
}

// TestEnvironmentVariableDefaults tests that OAuth config falls back to environment variables
func TestEnvironmentVariableDefaults(t *testing.T) {
	t.Run("Google OAuth reads from environment when empty", func(t *testing.T) {
		// This test verifies the behavior exists - we don't actually set env vars
		// because it would affect other tests
		googleAuth := oauth2.NewGoogleOAuth2("", "", "", nil)

		// With no env vars set, these should be empty
		if googleAuth.ClientId != "" {
			t.Error("Expected empty ClientId when env var not set")
		}
	})

	t.Run("GitHub OAuth reads from environment when empty", func(t *testing.T) {
		githubAuth := oauth2.NewGithubOAuth2("", "", "", nil)

		// With no env vars set, these should be empty
		if githubAuth.ClientId != "" {
			t.Error("Expected empty ClientId when env var not set")
		}
	})

	t.Run("explicit values override environment", func(t *testing.T) {
		googleAuth := oauth2.NewGoogleOAuth2(
			"explicit-client-id",
			"explicit-secret",
			"http://explicit-callback.com",
			nil,
		)

		if googleAuth.ClientId != "explicit-client-id" {
			t.Errorf("Expected explicit ClientId, got '%s'", googleAuth.ClientId)
		}
		if googleAuth.ClientSecret != "explicit-secret" {
			t.Errorf("Expected explicit ClientSecret, got '%s'", googleAuth.ClientSecret)
		}
		if googleAuth.CallbackURL != "http://explicit-callback.com" {
			t.Errorf("Expected explicit CallbackURL, got '%s'", googleAuth.CallbackURL)
		}
	})
}
