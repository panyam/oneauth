package apiauth_test

// A token that names its client only in `azp` belongs to that client for
// RFC 7009 revocation. Before issue 458 its ClientID was empty, and a token
// with no client could be revoked by any authenticated client.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.2
// See: https://cwe.mitre.org/data/definitions/639.html
// See: https://github.com/panyam/oneauth/issues/458

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func azpRevoker() (apiauth.TokenRevoker, *core.InMemoryBlacklist) {
	bl := core.NewInMemoryBlacklist()
	return apiauth.NewTokenRevoker(apiauth.TokenRevokerConfig{Blacklist: bl, Validator: azpValidator()}), bl
}

func TestRevocationAZP_OtherClientIsNotOwner(t *testing.T) {
	revoker, bl := azpRevoker()
	tok := signTimesToken(t, azpClaims("", "keycloak-client"))

	_, err := revoker.Revoke(context.Background(), &apiauth.RevokeRequest{Token: tok, ClientID: "someone-else"})

	assert.ErrorIs(t, err, apiauth.ErrRevokeNotOwner)
	assert.False(t, bl.IsRevoked("tok-1"))
}

func TestRevocationAZP_AZPClientRevokes(t *testing.T) {
	revoker, bl := azpRevoker()
	tok := signTimesToken(t, azpClaims("", "keycloak-client"))

	_, err := revoker.Revoke(context.Background(), &apiauth.RevokeRequest{Token: tok, ClientID: "keycloak-client"})

	require.NoError(t, err)
	assert.True(t, bl.IsRevoked("tok-1"))
}
