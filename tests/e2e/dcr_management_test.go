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
	"context"
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
	resp2, err := client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: regToken,
	})
	require.NoError(t, err)
	require.NotNil(t, resp2.Registration)
	got := resp2.Registration

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

	_, err := client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: "this-is-not-the-token",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrRegistrationUnauthorized)

	c.Delete("/apps/" + clientID)
}

// TestE2E_DCRManagement_UpdateRegistration drives the full RFC 7592 §2.2 PUT
// round trip against the real auth server: register → update scope → verify
// the GET reflects the new metadata using the *rotated* token. The original
// token must stop working after rotation — that's the security guarantee for
// post-update token leakage.
func TestE2E_DCRManagement_UpdateRegistration(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.PostJSON("/apps/dcr", map[string]any{
		"client_name": "PUT E2E",
		"scope":       "read",
	})
	require.Equal(t, 201, resp.StatusCode)
	dcr := ReadJSON(resp)
	clientID, _ := dcr["client_id"].(string)
	oldToken, _ := dcr["registration_access_token"].(string)
	regURI, _ := dcr["registration_client_uri"].(string)

	// PUT — change scope.
	updateResp, err := client.UpdateRegistration(context.Background(), &client.UpdateRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: oldToken,
		ClientID:                clientID,
		Metadata: client.ClientRegistrationRequest{
			ClientName: "PUT E2E Updated",
			Scope:      "read write",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, updateResp.Registration)
	updated := updateResp.Registration
	assert.Equal(t, "PUT E2E Updated", updated.ClientName)
	assert.Equal(t, "read write", updated.Scope)

	newToken := updated.RegistrationAccessToken
	require.NotEmpty(t, newToken)
	assert.NotEqual(t, oldToken, newToken, "AS must rotate the registration_access_token on PUT")

	// New token works for GET; old token is now rejected with 401.
	getResp, err := client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: newToken,
	})
	require.NoError(t, err)
	assert.Equal(t, "PUT E2E Updated", getResp.Registration.ClientName)

	_, err = client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: oldToken,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrRegistrationUnauthorized,
		"old token must be invalid after rotation")

	c.Delete("/apps/" + clientID)
}

// TestE2E_DCRManagement_PUT_BodyMismatchReturns400 verifies that the AS
// rejects a body whose client_id does not match the URL with HTTP 400
// (RFC 7592 §2.2 MUST). The SDK auto-fills the body so an explicit override
// to a wrong value is the realistic failure mode.
func TestE2E_DCRManagement_PUT_BodyMismatchReturns400(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.PostJSON("/apps/dcr", map[string]any{"client_name": "Body Mismatch"})
	require.Equal(t, 201, resp.StatusCode)
	dcr := ReadJSON(resp)
	clientID, _ := dcr["client_id"].(string)
	token, _ := dcr["registration_access_token"].(string)
	regURI, _ := dcr["registration_client_uri"].(string)

	// Send a body whose client_id is wrong on purpose.
	_, err := client.UpdateRegistration(context.Background(), &client.UpdateRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: token,
		ClientID:                clientID,
		Metadata: client.ClientRegistrationRequest{
			ClientID:   "app_other_id",
			ClientName: "Should Fail",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")

	c.Delete("/apps/" + clientID)
}
