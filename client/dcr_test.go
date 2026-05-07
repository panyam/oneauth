package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterClient_Success verifies the full RFC 7591 Dynamic Client
// Registration round-trip: the client POSTs a registration request and
// receives an assigned client_id and optional client_secret.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1
func TestRegisterClient_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req ClientRegistrationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "test-client", req.ClientName)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ClientRegistrationResponse{
			ClientID:     "assigned-id-123",
			ClientSecret: "assigned-secret-456",
		})
	}))
	defer server.Close()

	resp, err := RegisterClient(server.URL, ClientRegistrationRequest{
		ClientName:   "test-client",
		RedirectURIs: []string{"http://127.0.0.1:0/callback"},
	}, nil)

	require.NoError(t, err)
	assert.Equal(t, "assigned-id-123", resp.ClientID)
	assert.Equal(t, "assigned-secret-456", resp.ClientSecret)
}

// TestRegisterClient_ServerError verifies that non-success HTTP status codes
// from the DCR endpoint are surfaced as errors with the response body.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
func TestRegisterClient_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	_, err := RegisterClient(server.URL, ClientRegistrationRequest{
		ClientName: "test-client",
	}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// TestRegisterClient_EmptyClientID verifies that a DCR response with an
// empty client_id is treated as an error, since client_id is a required
// field in the registration response.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1
func TestRegisterClient_EmptyClientID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ClientRegistrationResponse{
			ClientID: "", // empty — invalid
		})
	}))
	defer server.Close()

	_, err := RegisterClient(server.URL, ClientRegistrationRequest{
		ClientName: "test-client",
	}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty client_id")
}

// TestRegisterClient_ParsesManagementCredentials verifies that registration_access_token
// and registration_client_uri (RFC 7592 §3) are deserialized into the response when the
// AS includes them, so callers can subsequently invoke GetRegistration / Update / Delete.
//
// See: https://www.rfc-editor.org/rfc/rfc7592#section-3
// See: https://github.com/panyam/oneauth/issues/168
func TestRegisterClient_ParsesManagementCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":                 "client-mgmt-1",
			"client_secret":             "s",
			"registration_access_token": "rat-token-xyz",
			"registration_client_uri":   "https://issuer.example/apps/dcr/client-mgmt-1",
		})
	}))
	defer server.Close()

	resp, err := RegisterClient(server.URL, ClientRegistrationRequest{ClientName: "x"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "rat-token-xyz", resp.RegistrationAccessToken)
	assert.Equal(t, "https://issuer.example/apps/dcr/client-mgmt-1", resp.RegistrationClientURI)
}

// TestGetRegistration_Success verifies the happy-path RFC 7592 GET round trip:
// the client sends Authorization: Bearer <registration_access_token> to the
// registration_client_uri and receives the parsed registration metadata.
//
// See: https://www.rfc-editor.org/rfc/rfc7592#section-2.1
func TestGetRegistration_Success(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "Bearer rat-good", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(ClientRegistrationResponse{
			ClientID:                "client-1",
			ClientName:              "Example Client",
			RedirectURIs:            []string{"https://app.example/cb"},
			RegistrationAccessToken: "rat-good",
			RegistrationClientURI:   serverURL,
		})
	}))
	defer server.Close()
	serverURL = server.URL

	resp, err := GetRegistration(server.URL, "rat-good", nil)
	require.NoError(t, err)
	assert.Equal(t, "client-1", resp.ClientID)
	assert.Equal(t, "Example Client", resp.ClientName)
	assert.Equal(t, []string{"https://app.example/cb"}, resp.RedirectURIs)
}

// TestGetRegistration_Unauthorized verifies that a 401 from the AS surfaces as
// ErrRegistrationUnauthorized so callers can branch on errors.Is. Per RFC 7592,
// the AS returns 401 for any auth failure (wrong token, missing token, unknown
// client_id), so this single error covers all of them.
func TestGetRegistration_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := GetRegistration(server.URL, "rat-bad", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRegistrationUnauthorized), "expected ErrRegistrationUnauthorized, got %v", err)
}

// TestGetRegistration_OtherErrors verifies that non-401 server errors include
// the status code and body in the returned error for diagnostics.
func TestGetRegistration_OtherErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := GetRegistration(server.URL, "rat", nil)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrRegistrationUnauthorized))
	assert.Contains(t, err.Error(), "500")
}

// TestGetRegistration_ValidatesArguments verifies that empty registration_client_uri
// or empty registration_access_token return validation errors before any network
// I/O, so misuse fails fast.
func TestGetRegistration_ValidatesArguments(t *testing.T) {
	_, err := GetRegistration("", "rat", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration_client_uri")

	_, err = GetRegistration("https://x", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration_access_token")
}
