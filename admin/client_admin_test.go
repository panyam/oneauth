// Tests for the transport-agnostic ClientRegistrar interface introduced in
// 172. The HTTP-level paths are exercised by registrar_test.go and dcr_test.go;
// this file calls the interface directly, demonstrating the manager is usable
// from in-process / gRPC / CLI callers without HTTP machinery.
package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/panyam/oneauth/core"
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
	store := core.NewInMemoryAppStore()
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
	stored, err := store.GetApp(context.Background(), &core.GetAppRequest{ClientID: got.ClientID})
	require.NoError(t, err)
	assert.Equal(t, "Direct Invoke", stored.App.ClientName)
}

// TestClientRegistrar_ListClients_ReflectsRegistrations verifies that
// successive Register calls show up in ListClients in the expected count,
// and the returned entries are clones (mutating one does not affect the cache).
func TestClientRegistrar_ListClients_ReflectsRegistrations(t *testing.T) {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())

	_, err := r.Register(context.Background(), &admin.RegisterRequest{Metadata: &admin.DCRRequest{ClientName: "A"}})
	require.NoError(t, err)
	_, err = r.Register(context.Background(), &admin.RegisterRequest{Metadata: &admin.DCRRequest{ClientName: "B"}})
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
	assert.True(t, errors.Is(err, core.ErrAppNotFound))
}

// TestClientRegistrar_DeleteClient_RemovesFromStoreAndKeyStore verifies the
// full effect of admin-side delete: registration gone from the store AND
// signing key gone from KeyStore (so already-issued tokens fail validation).
func TestClientRegistrar_DeleteClient_RemovesFromStoreAndKeyStore(t *testing.T) {
	store := core.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()
	r := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)

	resp, err := r.Register(context.Background(), &admin.RegisterRequest{Metadata: &admin.DCRRequest{ClientName: "doomed"}})
	require.NoError(t, err)
	clientID := resp.Registration.ClientID

	_, err = r.DeleteClient(context.Background(), &admin.DeleteClientRequest{ClientID: clientID})
	require.NoError(t, err)

	// Store side: gone.
	if _, err := store.GetApp(context.Background(), &core.GetAppRequest{ClientID: clientID}); !errors.Is(err, core.ErrAppNotFound) {
		t.Errorf("store should report ErrAppNotFound after DeleteClient, got %v", err)
	}
	// KeyStore side: gone.
	if _, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID}); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("KeyStore should report ErrKeyNotFound after DeleteClient, got %v", err)
	}
	// Repeat delete: ErrAppNotFound (idempotency by accident — safe).
	_, err = r.DeleteClient(context.Background(), &admin.DeleteClientRequest{ClientID: clientID})
	assert.True(t, errors.Is(err, core.ErrAppNotFound))
}

// TestClientRegistrar_RotateSecret_Symmetric verifies that rotating a
// symmetric client returns a fresh secret + new kid, both distinct from the
// pre-rotation values.
func TestClientRegistrar_RotateSecret_Symmetric(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	r := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), core.NewInMemoryAppStore())

	regResp, err := r.Register(context.Background(), &admin.RegisterRequest{Metadata: &admin.DCRRequest{ClientName: "rotate.me"}})
	require.NoError(t, err)
	registered := regResp.Registration

	preRotateKeyResp_, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: registered.ClientID})
	var preRotateKey *keys.KeyRecord
	if preRotateKeyResp_ != nil {
		preRotateKey = preRotateKeyResp_.Record
	}
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
