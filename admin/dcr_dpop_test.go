package admin_test

// RFC 9449 §5.2 dpop_bound_access_tokens on DCR: a client that registers it
// gets it echoed, persisted, returned on read, and changeable on update.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5.2
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
)

func TestDCR_DPoPBoundAccessTokens_RoundTrips(t *testing.T) {
	_, registrar, resp := registerAppWithBCL(t, `{"client_name":"DPoP Client","dpop_bound_access_tokens":true}`)
	ctx := context.Background()

	assert.Equal(t, true, resp["dpop_bound_access_tokens"])
	clientID := resp["client_id"].(string)
	token := resp["registration_access_token"].(string)

	stored, err := registrar.Store.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	require.NoError(t, err)
	assert.True(t, stored.App.DPoPBoundAccessTokens, "persisted, not just echoed")

	read, err := registrar.GetRegistration(ctx, &admin.GetRegistrationRequest{ClientID: clientID, AccessToken: token})
	require.NoError(t, err)
	assert.True(t, read.Registration.DPoPBoundAccessTokens)

	updated, err := registrar.UpdateRegistration(ctx, &admin.UpdateRegistrationRequest{
		ClientID: clientID, AccessToken: token,
		Metadata: &admin.DCRRequest{ClientID: clientID, ClientName: "DPoP Client", DPoPBoundAccessTokens: false},
	})
	require.NoError(t, err)
	assert.False(t, updated.Registration.DPoPBoundAccessTokens)
	stored, err = registrar.Store.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	require.NoError(t, err)
	assert.False(t, stored.App.DPoPBoundAccessTokens)
}

// Absent means false, and the response leaves the member out.
func TestDCR_DPoPBoundAccessTokens_DefaultsOff(t *testing.T) {
	_, registrar, resp := registerAppWithBCL(t, `{"client_name":"Plain Client"}`)

	_, present := resp["dpop_bound_access_tokens"]
	assert.False(t, present)
	stored, err := registrar.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: resp["client_id"].(string)})
	require.NoError(t, err)
	assert.False(t, stored.App.DPoPBoundAccessTokens)
}
