package keycloak_test

// A Keycloak user token names its client only in azp. Keycloak refuses to
// let another client revoke it, and a oneauth revoker that validates
// Keycloak's tokens through its JWKS now refuses too. Before issue 458 the
// token had no ClientID on the oneauth side, so any client could revoke it.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://cwe.mitre.org/data/definitions/639.html
// See: https://github.com/panyam/oneauth/issues/458

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

func keycloakBackedRevoker(t *testing.T) (apiauth.TokenRevoker, *core.InMemoryBlacklist) {
	t.Helper()
	jwks := keys.NewJWKSKeyStore(realmURL() + "/protocol/openid-connect/certs")
	require.NoError(t, jwks.Start())
	t.Cleanup(jwks.Stop)
	bl := core.NewInMemoryBlacklist()
	return apiauth.NewTokenRevoker(apiauth.TokenRevokerConfig{
		Blacklist: bl,
		Validator: apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{KeyLookup: jwks, Issuer: realmURL()}),
	}), bl
}

func TestKeycloakRevocationAZP_OwnershipMatchesKeycloak(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)
	tok := getPasswordToken(t, cfg.TokenEndpoint, confidentialClientID, confidentialClientSecret, testUsername, testPassword).AccessToken
	claims := parseJWTClaims(t, tok)
	require.Equal(t, confidentialClientID, claims["azp"])
	require.Nil(t, claims["client_id"], "this test needs a token that names its client only in azp")
	jti, _ := claims["jti"].(string)
	require.NotEmpty(t, jti)
	revoker, bl := keycloakBackedRevoker(t)

	t.Run("another client is refused by both", func(t *testing.T) {
		kcRevoke := strings.TrimSuffix(cfg.TokenEndpoint, "/token") + "/revoke"
		got := revoke(t, kcRevoke, url.Values{"token": {tok}}, audienceClientID, audienceClientSecret)
		assert.Equal(t, answer{Status: http.StatusBadRequest, Error: "invalid_request"}, got, "keycloak")

		_, err := revoker.Revoke(context.Background(), &apiauth.RevokeRequest{Token: tok, ClientID: audienceClientID})
		assert.ErrorIs(t, err, apiauth.ErrRevokeNotOwner, "oneauth")
		assert.False(t, bl.IsRevoked(jti))
	})

	t.Run("the azp client revokes it", func(t *testing.T) {
		_, err := revoker.Revoke(context.Background(), &apiauth.RevokeRequest{Token: tok, ClientID: confidentialClientID})
		require.NoError(t, err)
		assert.True(t, bl.IsRevoked(jti))
	})
}
