// Tests for the transport-agnostic ClientRegistrar interface introduced in
// 172. The HTTP-level paths are exercised by registrar_test.go and dcr_test.go;
// this file calls the interface directly, demonstrating the manager is usable
// from in-process / gRPC / CLI callers without HTTP machinery.
package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientRegistrar_Register_DirectInvocation drives RFC 7591 registration
// through the manager interface (no HTTP). Confirms the response carries the
// RFC 7592 management credentials and the registration is persisted in the
// store.
func TestClientRegistrar_Register_DirectInvocation(t *testing.T) {
	store := admin.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()
	r := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)

	resp, err := r.Register(context.Background(), &admin.RegisterRequest{
		Metadata: &admin.DCRRequest{
			ClientName: "Direct Invoke",
			GrantTypes: []string{"client_credentials"},
		},
		IssuerBaseURL: "https://issuer.example",
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Registration)

	got := resp.Registration
	assert.NotEmpty(t, got.ClientID, "client_id assigned")
	assert.NotEmpty(t, got.ClientSecret, "symmetric default → client_secret issued")
	assert.NotEmpty(t, got.RegistrationAccessToken, "RFC 7592 §3 management token issued")
	assert.Contains(t, got.RegistrationClientURI, "https://issuer.example/apps/dcr/")

	// Persisted: the same client_id is retrievable from the store directly.
	stored, err := store.GetApp(got.ClientID)
	require.NoError(t, err)
	assert.Equal(t, "Direct Invoke", stored.ClientName)
}

// TestClientRegistrar_RegisterLegacy_DirectInvocation verifies the proprietary
// /apps/register path works through the manager interface, including the
// OneAuth-specific quota fields.
func TestClientRegistrar_RegisterLegacy_DirectInvocation(t *testing.T) {
	store := admin.NewInMemoryAppStore()
	r := admin.NewAppRegistrarWithStore(keys.NewInMemoryKeyStore(), admin.NewNoAuth(), store)

	resp, err := r.RegisterLegacy(context.Background(), &admin.RegisterLegacyRequest{
		ClientDomain: "legacy.example",
		MaxRooms:     50,
		MaxMsgRate:   2.5,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ClientID)
	assert.Equal(t, "HS256", resp.SigningAlg, "default alg")
	assert.NotEmpty(t, resp.ClientSecret, "symmetric → secret issued")
	assert.Equal(t, 50, resp.MaxRooms, "OneAuth-specific quota field surfaced")
	assert.Equal(t, 2.5, resp.MaxMsgRate)

	stored, err := store.GetApp(resp.ClientID)
	require.NoError(t, err)
	assert.Equal(t, 50, stored.MaxRooms, "quota persisted on AppRegistration")
}

// TestClientRegistrar_RegisterLegacy_AsymmetricRequiresPublicKey verifies the
// validation error path: asymmetric algs without public_key surface as
// ErrPublicKeyRequired (mapped to HTTP 400 by the wrapper).
func TestClientRegistrar_RegisterLegacy_AsymmetricRequiresPublicKey(t *testing.T) {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())

	_, err := r.RegisterLegacy(context.Background(), &admin.RegisterLegacyRequest{
		ClientDomain: "rs256.example",
		SigningAlg:   "RS256",
		// PublicKey intentionally empty
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, admin.ErrPublicKeyRequired),
		"asymmetric register without public_key must return ErrPublicKeyRequired")
}

// TestClientRegistrar_ListClients_ReflectsRegistrations verifies that
// successive Register / RegisterLegacy calls show up in ListClients in the
// expected count, and the returned entries are clones (mutating one does not
// affect the cache).
func TestClientRegistrar_ListClients_ReflectsRegistrations(t *testing.T) {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())

	_, err := r.Register(context.Background(), &admin.RegisterRequest{Metadata: &admin.DCRRequest{ClientName: "A"}})
	require.NoError(t, err)
	_, err = r.RegisterLegacy(context.Background(), &admin.RegisterLegacyRequest{ClientDomain: "b.example"})
	require.NoError(t, err)

	resp, err := r.ListClients(context.Background(), &admin.ListClientsRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.Apps, 2)

	// Mutating the returned slice should not leak into a subsequent ListClients.
	resp.Apps[0].ClientName = "MUTATED"
	resp2, _ := r.ListClients(context.Background(), &admin.ListClientsRequest{})
	for _, app := range resp2.Apps {
		assert.NotEqual(t, "MUTATED", app.ClientName, "ListClients must return clones")
	}
}

// TestClientRegistrar_GetClient_NotFound verifies the typed error contract
// callers rely on for distinguishing missing-client from server failures.
func TestClientRegistrar_GetClient_NotFound(t *testing.T) {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())

	_, err := r.GetClient(context.Background(), &admin.GetClientRequest{ClientID: "app_phantom"})
	assert.True(t, errors.Is(err, admin.ErrAppNotFound))
}

// TestClientRegistrar_DeleteClient_RemovesFromStoreAndKeyStore verifies the
// full effect of admin-side delete: registration gone from the store AND
// signing key gone from KeyStore (so already-issued tokens fail validation).
func TestClientRegistrar_DeleteClient_RemovesFromStoreAndKeyStore(t *testing.T) {
	store := admin.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()
	r := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)

	resp, err := r.RegisterLegacy(context.Background(), &admin.RegisterLegacyRequest{ClientDomain: "doomed"})
	require.NoError(t, err)
	clientID := resp.ClientID

	_, err = r.DeleteClient(context.Background(), &admin.DeleteClientRequest{ClientID: clientID})
	require.NoError(t, err)

	// Store side: gone.
	if _, err := store.GetApp(clientID); !errors.Is(err, admin.ErrAppNotFound) {
		t.Errorf("store should report ErrAppNotFound after DeleteClient, got %v", err)
	}
	// KeyStore side: gone.
	if _, err := ks.GetKey(clientID); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("KeyStore should report ErrKeyNotFound after DeleteClient, got %v", err)
	}
	// Repeat delete: ErrAppNotFound (idempotency by accident — safe).
	_, err = r.DeleteClient(context.Background(), &admin.DeleteClientRequest{ClientID: clientID})
	assert.True(t, errors.Is(err, admin.ErrAppNotFound))
}

// TestClientRegistrar_RotateSecret_Symmetric verifies that rotating a
// symmetric client returns a fresh secret + new kid, both distinct from the
// pre-rotation values.
func TestClientRegistrar_RotateSecret_Symmetric(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	r := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), admin.NewInMemoryAppStore())

	registered, err := r.RegisterLegacy(context.Background(), &admin.RegisterLegacyRequest{ClientDomain: "rotate.me"})
	require.NoError(t, err)

	preRotateKey, err := ks.GetKey(registered.ClientID)
	require.NoError(t, err)
	preRotateKid := preRotateKey.Kid

	rotated, err := r.RotateSecret(context.Background(), &admin.RotateSecretRequest{ClientID: registered.ClientID})
	require.NoError(t, err)
	assert.Equal(t, registered.ClientID, rotated.ClientID)
	assert.NotEmpty(t, rotated.ClientSecret, "symmetric rotation issues a new secret")
	assert.NotEqual(t, registered.ClientSecret, rotated.ClientSecret, "secret must actually change")
	assert.NotEmpty(t, rotated.Kid, "kid populated from new key material")
	assert.NotEqual(t, preRotateKid, rotated.Kid, "kid must change with the secret")
}
