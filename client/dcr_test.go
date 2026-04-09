package client

import (
	"encoding/json"
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
