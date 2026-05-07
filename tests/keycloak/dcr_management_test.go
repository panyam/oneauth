package keycloak_test

// Keycloak interop tests for OAuth 2.0 Dynamic Client Registration Management
// (RFC 7592) — proves OneAuth's client SDK helpers (GetRegistration,
// UpdateRegistration, DeleteRegistration) speak the same wire format as a
// real-world AS, not just the OneAuth server.
//
// Prerequisites:
//   - Keycloak running with the realm imported from realm.json (anonymous DCR
//     enabled via the relaxed Trusted Hosts policy in `components`).
//   - Run: make upkcl  (starts the container)
//   - Run: make testkcl (runs all interop tests)
//
// Tests skip gracefully when Keycloak is not reachable.
//
// References:
//   - RFC 7591 (https://www.rfc-editor.org/rfc/rfc7591): DCR
//   - RFC 7592 (https://www.rfc-editor.org/rfc/rfc7592): DCR Management
//   - See: https://github.com/panyam/oneauth/issues/171

import (
	"context"
	"errors"
	"testing"

	"github.com/panyam/oneauth/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeycloak_DCRManagement_Lifecycle exercises the full RFC 7592 verb trio
// (register → GET → PUT → DELETE) against Keycloak via the OneAuth client SDK.
// One cohesive test rather than per-verb because the lifecycle IS the
// integration story, and KC's startup time means we want one round trip per
// run, not N.
//
// What this proves:
//   - KC issues registration_access_token + registration_client_uri at
//     registration (RFC 7592 §3) — confirms our SDK's parsing is bytewise
//     compatible with KC's wire format.
//   - GET round-trips client metadata using only the registration access token.
//   - PUT replaces metadata AND rotates the registration_access_token. Old
//     token is rejected on subsequent calls — same security guarantee we
//     ship in OneAuth.
//   - DELETE returns success and the registration is gone (subsequent GET
//     fails with the expected 401-mapped sentinel).
func TestKeycloak_DCRManagement_Lifecycle(t *testing.T) {
	skipIfKeycloakNotRunning(t)

	// 1. Discover the registration endpoint.
	cfg := discoverOIDC(t)
	require.NotEmpty(t, cfg.RegistrationEndpoint, "Keycloak must advertise registration_endpoint")

	// 2. Register a client. Use grant_types=client_credentials so we don't
	//    need redirect_uris (which Keycloak otherwise validates against
	//    its allowed protocols / scopes for authorization_code clients).
	registered, err := client.RegisterClient(cfg.RegistrationEndpoint,
		client.ClientRegistrationRequest{
			ClientName:              "OneAuth interop probe (#171)",
			GrantTypes:              []string{"client_credentials"},
			TokenEndpointAuthMethod: "client_secret_post",
		}, nil)
	require.NoError(t, err, "DCR registration against Keycloak failed")
	require.NotEmpty(t, registered.ClientID, "Keycloak must assign a client_id")
	require.NotEmpty(t, registered.RegistrationAccessToken,
		"Keycloak must issue a registration_access_token on DCR (RFC 7592 §3)")
	require.NotEmpty(t, registered.RegistrationClientURI,
		"Keycloak must issue a registration_client_uri on DCR (RFC 7592 §3)")

	clientID := registered.ClientID
	regURI := registered.RegistrationClientURI
	tok := registered.RegistrationAccessToken

	// Defensive cleanup: if the test fails part-way, still try to delete
	// the orphaned KC client so the realm doesn't accumulate cruft across
	// runs. A second DELETE after the test's own DELETE is a no-op (401).
	t.Cleanup(func() {
		_, _ = client.DeleteRegistration(context.Background(), &client.DeleteRegistrationRequest{
			RegistrationClientURI:   regURI,
			RegistrationAccessToken: tok,
		})
	})

	// 3. GET — read the registration with the issued token.
	getResp, err := client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: tok,
	})
	require.NoError(t, err, "GET against Keycloak management endpoint failed")
	require.NotNil(t, getResp.Registration)
	assert.Equal(t, clientID, getResp.Registration.ClientID,
		"GET must echo the registered client_id")
	assert.Equal(t, "OneAuth interop probe (#171)", getResp.Registration.ClientName)

	// 4. PUT — update the client_name and verify Keycloak rotates the token
	//    per RFC 7592 §2.2. The old token must be rejected after rotation.
	updateResp, err := client.UpdateRegistration(context.Background(), &client.UpdateRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: tok,
		ClientID:                clientID,
		Metadata: client.ClientRegistrationRequest{
			ClientName:              "OneAuth interop probe (renamed)",
			GrantTypes:              []string{"client_credentials"},
			TokenEndpointAuthMethod: "client_secret_post",
		},
	})
	require.NoError(t, err, "PUT against Keycloak management endpoint failed")
	require.NotNil(t, updateResp.Registration)
	assert.Equal(t, "OneAuth interop probe (renamed)", updateResp.Registration.ClientName)

	newTok := updateResp.Registration.RegistrationAccessToken
	require.NotEmpty(t, newTok, "Keycloak must return a registration_access_token on PUT")
	assert.NotEqual(t, tok, newTok,
		"Keycloak should rotate the registration_access_token per RFC 7592 §2.2")
	tok = newTok // shift so cleanup uses the live token if DELETE below fails

	// Old token must be rejected on subsequent management calls.
	_, err = client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: registered.RegistrationAccessToken, // the original (rotated-out) token
	})
	require.Error(t, err, "Keycloak must reject the old token after rotation")
	assert.True(t, errors.Is(err, client.ErrRegistrationUnauthorized),
		"old-token rejection should map to ErrRegistrationUnauthorized, got %v", err)

	// 5. DELETE — remove the registration with the rotated token.
	_, err = client.DeleteRegistration(context.Background(), &client.DeleteRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: tok,
	})
	require.NoError(t, err, "DELETE against Keycloak management endpoint failed")

	// 6. Post-delete: GET must fail. KC may return 401 (matching our model)
	//    or 404; either way the SDK surfaces an error, and a 401 is mapped
	//    to ErrRegistrationUnauthorized.
	_, err = client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
		RegistrationClientURI:   regURI,
		RegistrationAccessToken: tok,
	})
	require.Error(t, err, "Keycloak must reject management calls after DELETE")
}
