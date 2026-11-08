package apiauth_test

// Keycloak names the client of a user's access token in `azp` and sends no
// `client_id`. TokenInfo.ClientID falls back to `azp`, so a resource server
// and the revocation ownership check both see the client. When a token
// carries both, `client_id` wins, since RFC 9068 §2.2 names it.
//
// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.2
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
// See: https://github.com/panyam/oneauth/issues/458

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
)

func azpClaims(clientID, azp string) jwt.MapClaims {
	claims := timesClaims()
	delete(claims, "client_id")
	if clientID != "" {
		claims["client_id"] = clientID
	}
	if azp != "" {
		claims["azp"] = azp
	}
	return claims
}

func azpValidator() apiauth.TokenValidator {
	return apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{
		KeyLookup:  keys.NewInMemoryKeyStore(),
		SigningKey: []byte(rsSecret), SigningAlg: "HS256", Issuer: rsIssuer,
	})
}

func TestTokenInfoAZP_ClientIDFallsBackToAZP(t *testing.T) {
	tok := signTimesToken(t, azpClaims("", "keycloak-client"))

	t.Run("validator", func(t *testing.T) {
		resp, err := azpValidator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: tok})
		require.NoError(t, err)
		assert.Equal(t, "keycloak-client", resp.Info.ClientID)
	})
	t.Run("inline", func(t *testing.T) {
		assert.Equal(t, "keycloak-client", infoFromHandler(t, bearerMiddleware(), tok).ClientID)
	})
}

func TestTokenInfoAZP_ClientIDClaimWins(t *testing.T) {
	tok := signTimesToken(t, azpClaims("issued-to", "presenter"))

	t.Run("validator", func(t *testing.T) {
		resp, err := azpValidator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: tok})
		require.NoError(t, err)
		assert.Equal(t, "issued-to", resp.Info.ClientID)
	})
	t.Run("inline", func(t *testing.T) {
		assert.Equal(t, "issued-to", infoFromHandler(t, bearerMiddleware(), tok).ClientID)
	})
}

func TestTokenInfoAZP_NeitherClaimLeavesClientIDEmpty(t *testing.T) {
	tok := signTimesToken(t, azpClaims("", ""))

	resp, err := azpValidator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: tok})

	require.NoError(t, err)
	assert.Empty(t, resp.Info.ClientID)
}

// The RFC 7662 client_id our introspection endpoint reports agrees with
// TokenInfo.ClientID.
func TestTokenInfoAZP_IntrospectionReportsAZPClient(t *testing.T) {
	tok := signTimesToken(t, azpClaims("", "keycloak-client"))

	resp, err := apiauth.NewTokenIntrospector(azpValidator()).Introspect(context.Background(), &apiauth.IntrospectRequest{Token: tok})

	require.NoError(t, err)
	require.True(t, resp.Result.Active)
	assert.Equal(t, "keycloak-client", resp.Result.ClientID)
}
