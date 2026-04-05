package apiauth_test

// Tests for the IntrospectionValidator client (RFC 7662 consumer side).
// Validates tokens by querying a remote introspection endpoint, as an
// alternative to local JWT validation via JWKS.
//
// References:
//   - RFC 7662 (https://www.rfc-editor.org/rfc/rfc7662):
//     "OAuth 2.0 Token Introspection"
//   - See: https://github.com/panyam/oneauth/issues/55

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockIntrospectionServer creates a test server that serves RFC 7662
// introspection responses. Validates Basic auth credentials.
func mockIntrospectionServer(t *testing.T, clientID, clientSecret string, responses map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != clientID || pass != clientSecret {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		r.ParseForm()
		token := r.FormValue("token")

		w.Header().Set("Content-Type", "application/json")
		if resp, ok := responses[token]; ok {
			json.NewEncoder(w).Encode(resp)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"active": false})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestIntrospectionClient_ActiveToken verifies that the validator correctly
// parses an active token response from the introspection endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospectionClient_ActiveToken(t *testing.T) {
	srv := mockIntrospectionServer(t, "rs-client", "rs-secret", map[string]any{
		"valid-token": map[string]any{
			"active":     true,
			"sub":        "user-42",
			"scope":      "read write",
			"client_id":  "app-123",
			"token_type": "access_token",
			"iss":        "https://auth.example.com",
		},
	})

	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: srv.URL,
		ClientID:         "rs-client",
		ClientSecret:     "rs-secret",
	}

	result, err := validator.Validate("valid-token")
	require.NoError(t, err)
	assert.True(t, result.Active)
	assert.Equal(t, "user-42", result.Sub)
	assert.Equal(t, "read write", result.Scope)
	assert.Equal(t, "app-123", result.ClientID)
	assert.Equal(t, "https://auth.example.com", result.Iss)
}

// TestIntrospectionClient_InactiveToken verifies that inactive tokens are
// returned as IntrospectionResult{Active: false} without error.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospectionClient_InactiveToken(t *testing.T) {
	srv := mockIntrospectionServer(t, "rs", "secret", nil) // all tokens return inactive

	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: srv.URL,
		ClientID:         "rs",
		ClientSecret:     "secret",
	}

	result, err := validator.Validate("expired-token")
	require.NoError(t, err)
	assert.False(t, result.Active)
}

// TestIntrospectionClient_AuthFailure verifies that wrong client credentials
// to the introspection endpoint return an error (not an inactive result).
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
func TestIntrospectionClient_AuthFailure(t *testing.T) {
	srv := mockIntrospectionServer(t, "rs", "correct-secret", nil)

	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: srv.URL,
		ClientID:         "rs",
		ClientSecret:     "wrong-secret",
	}

	_, err := validator.Validate("any-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth failed")
}

// TestIntrospectionClient_ValidateForMiddleware verifies that
// ValidateForMiddleware correctly extracts userID, scopes, and custom claims
// from an introspection response for use by APIMiddleware.
//
// See: https://github.com/panyam/oneauth/issues/55
func TestIntrospectionClient_ValidateForMiddleware(t *testing.T) {
	srv := mockIntrospectionServer(t, "rs", "secret", map[string]any{
		"my-token": map[string]any{
			"active":    true,
			"sub":       "user-99",
			"scope":     "read write admin",
			"client_id": "app-xyz",
			"iss":       "https://auth.example.com",
		},
	})

	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: srv.URL,
		ClientID:         "rs",
		ClientSecret:     "secret",
	}

	userID, scopes, authType, customClaims, err := validator.ValidateForMiddleware("my-token")
	require.NoError(t, err)
	assert.Equal(t, "user-99", userID)
	assert.Equal(t, []string{"read", "write", "admin"}, scopes)
	assert.Equal(t, "introspection", authType)
	assert.Equal(t, "app-xyz", customClaims["client_id"])
	assert.Equal(t, "https://auth.example.com", customClaims["iss"])
}

// TestIntrospectionClient_ValidateForMiddleware_Inactive verifies that
// ValidateForMiddleware returns an error for inactive tokens.
func TestIntrospectionClient_ValidateForMiddleware_Inactive(t *testing.T) {
	srv := mockIntrospectionServer(t, "rs", "secret", nil)

	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: srv.URL,
		ClientID:         "rs",
		ClientSecret:     "secret",
	}

	_, _, _, _, err := validator.ValidateForMiddleware("bad-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

// TestIntrospectionClient_Caching verifies that responses are cached when
// CacheTTL is set. The second call should not hit the server.
func TestIntrospectionClient_Caching(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		user, pass, _ := r.BasicAuth()
		if user != "rs" || pass != "secret" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "cached-user",
			"scope":  "read",
		})
	}))
	defer srv.Close()

	validator := &apiauth.IntrospectionValidator{
		IntrospectionURL: srv.URL,
		ClientID:         "rs",
		ClientSecret:     "secret",
		CacheTTL:         5 * time.Second,
	}

	// First call — hits server
	result1, err := validator.Validate("cacheable-token")
	require.NoError(t, err)
	assert.True(t, result1.Active)
	assert.Equal(t, 1, callCount)

	// Second call — should use cache
	result2, err := validator.Validate("cacheable-token")
	require.NoError(t, err)
	assert.True(t, result2.Active)
	assert.Equal(t, 1, callCount, "second call should use cache, not hit server")
}

// TestIntrospectionClient_MiddlewareIntegration verifies that
// IntrospectionValidator works as a fallback in APIMiddleware when
// local JWT validation is not configured.
//
// See: https://github.com/panyam/oneauth/issues/55
func TestIntrospectionClient_MiddlewareIntegration(t *testing.T) {
	srv := mockIntrospectionServer(t, "rs", "secret", map[string]any{
		"opaque-token-123": map[string]any{
			"active":    true,
			"sub":       "service-account",
			"scope":     "read",
			"client_id": "billing-svc",
		},
	})

	// APIMiddleware with NO local JWT config — only introspection
	middleware := &apiauth.APIMiddleware{
		Introspection: &apiauth.IntrospectionValidator{
			IntrospectionURL: srv.URL,
			ClientID:         "rs",
			ClientSecret:     "secret",
		},
	}

	var extractedUserID string
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedUserID = apiauth.GetUserIDFromAPIContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer opaque-token-123")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code,
		"middleware should accept token validated via introspection")
	assert.Equal(t, "service-account", extractedUserID)
}
