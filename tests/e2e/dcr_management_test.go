package e2e_test

// E2E for the RFC 7592 management protocol — proves that a client registered
// via DCR can subsequently fetch its own registration using the management
// credentials returned at registration time, end to end through the real auth
// server. The client SDK helper (client.GetRegistration) is exercised here so
// regressions in the wire format on either side are caught immediately.
//
// References:
//   - RFC 7592 §2.1 — Read Client Registration
//   - https://github.com/panyam/oneauth/issues/168

import (
	"testing"

	"github.com/panyam/oneauth/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_DCRManagement_GetRegistration registers a client via DCR against
// the real auth server, then uses the issued registration_access_token +
// registration_client_uri to call the management GET endpoint. It verifies
// the round-trip preserves all the metadata the client supplied at
// registration, and that the management response intentionally omits
// client_secret.
func TestE2E_DCRManagement_GetRegistration(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	// Register a client via DCR with rich metadata so we can verify the
	// management response echoes it back correctly.
	resp := c.PostJSON("/apps/dcr", map[string]any{
		"client_name":   "E2E Mgmt Client",
		"client_uri":    "https://e2e.example",
		"redirect_uris": []string{"https://e2e.example/cb"},
		"grant_types":   []string{"client_credentials"},
		"scope":         "read write",
	})
	require.Equal(t, 201, resp.StatusCode)
	dcr := ReadJSON(resp)

	clientID, _ := dcr["client_id"].(string)
	clientSecret, _ := dcr["client_secret"].(string)
	regToken, _ := dcr["registration_access_token"].(string)
	regURI, _ := dcr["registration_client_uri"].(string)

	require.NotEmpty(t, clientID, "DCR must issue client_id")
	require.NotEmpty(t, clientSecret, "DCR must issue client_secret for symmetric")
	require.NotEmpty(t, regToken, "DCR must issue registration_access_token (RFC 7592 §3)")
	require.NotEmpty(t, regURI, "DCR must issue registration_client_uri (RFC 7592 §3)")

	// Drive the SDK against the live management endpoint.
	got, err := client.GetRegistration(regURI, regToken, nil)
	require.NoError(t, err)

	assert.Equal(t, clientID, got.ClientID, "GET must echo the registered client_id")
	assert.Equal(t, "E2E Mgmt Client", got.ClientName)
	assert.Equal(t, "https://e2e.example", got.ClientURI)
	assert.Equal(t, []string{"https://e2e.example/cb"}, got.RedirectURIs)
	assert.Equal(t, []string{"client_credentials"}, got.GrantTypes)
	assert.Equal(t, "read write", got.Scope)
	assert.Equal(t, regToken, got.RegistrationAccessToken)

	// Per security note in DCRManagementHandler.handleGet, client_secret must
	// NOT be echoed on read.
	assert.Empty(t, got.ClientSecret, "GET response must NOT include client_secret")

	// Cleanup so the test environment doesn't accumulate state across runs.
	c.Delete("/apps/" + clientID)
}

// TestE2E_DCRManagement_WrongTokenReturns401 verifies the wire-level rejection
// path: hitting the live management endpoint with a wrong token yields 401
// (mapped to ErrRegistrationUnauthorized by the SDK).
func TestE2E_DCRManagement_WrongTokenReturns401(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.PostJSON("/apps/dcr", map[string]any{"client_name": "Wrong Token E2E"})
	require.Equal(t, 201, resp.StatusCode)
	dcr := ReadJSON(resp)
	clientID, _ := dcr["client_id"].(string)
	regURI, _ := dcr["registration_client_uri"].(string)

	_, err := client.GetRegistration(regURI, "this-is-not-the-token", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrRegistrationUnauthorized)

	c.Delete("/apps/" + clientID)
}
