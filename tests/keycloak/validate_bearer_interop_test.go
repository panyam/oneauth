package keycloak_test

// ValidateBearer and the TokenInfo times against Keycloak-issued tokens. A
// resource server re-authenticating over an open channel validates
// Keycloak's tokens through its JWKS, and has to read exp from the verified
// token rather than re-parsing it.
//
// References:
//   - RFC 7519 §4.1 (https://www.rfc-editor.org/rfc/rfc7519#section-4.1)
//   - RFC 9449 §7.2 (https://www.rfc-editor.org/rfc/rfc9449#section-7.2)
//   - RFC 7662 §2.2 (https://www.rfc-editor.org/rfc/rfc7662#section-2.2)
//   - See: https://github.com/panyam/oneauth/issues/456

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func claimTime(t *testing.T, claims map[string]any, name string) time.Time {
	t.Helper()
	v, ok := claims[name].(float64)
	require.True(t, ok, "Keycloak token has no numeric %s: %v", name, claims[name])
	return time.Unix(int64(v), 0)
}

// The times and jti on TokenInfo equal the claims Keycloak put in the token.
// ClientID equals client_id when Keycloak sends one, and azp when it names
// the client only there, as it does for a password-grant token.
func TestKeycloakValidateBearer_TokenInfoMatchesClaims(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	_, mw := newKeycloakBackedResource(t)
	tok := getPasswordToken(t, realmURL()+"/protocol/openid-connect/token",
		confidentialClientID, confidentialClientSecret, testUsername, testPassword)
	claims := parseJWTClaims(t, tok.AccessToken)

	resp, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: tok.AccessToken})

	require.NoError(t, err)
	info := resp.Info
	assert.True(t, info.ExpiresAt.Equal(claimTime(t, claims, "exp")), "ExpiresAt = %v", info.ExpiresAt)
	assert.True(t, info.IssuedAt.Equal(claimTime(t, claims, "iat")), "IssuedAt = %v", info.IssuedAt)
	jti, _ := claims["jti"].(string)
	assert.Equal(t, jti, info.TokenID)
	clientID, _ := claims["client_id"].(string)
	if clientID == "" {
		clientID, _ = claims["azp"].(string)
	}
	assert.Equal(t, confidentialClientID, clientID, "Keycloak names the client in client_id or azp")
	assert.Equal(t, clientID, info.ClientID)
}

func TestKeycloakValidateBearer_DPoPBoundToken(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key := newDPoPKey(t)
	token := keycloakDPoPToken(t, key)
	_, mw := newKeycloakBackedResource(t)
	confirmFor := func(jkt string) func(context.Context, *core.Confirmation) error {
		return func(_ context.Context, cnf *core.Confirmation) error {
			if cnf.JKT != jkt {
				return errors.New("token is bound to a different key than this channel")
			}
			return nil
		}
	}
	validate := func(confirm func(context.Context, *core.Confirmation) error) error {
		_, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: token, ConfirmBinding: confirm})
		return err
	}

	t.Run("refused without ConfirmBinding", func(t *testing.T) {
		var ae *apiauth.AuthError
		require.ErrorAs(t, validate(nil), &ae)
		assert.Equal(t, "invalid_token", ae.Code)
		assert.Equal(t, apiauth.TokenTypeDPoP, ae.Scheme)
	})

	t.Run("accepted for the key Keycloak bound it to", func(t *testing.T) {
		require.NoError(t, validate(confirmFor(key.jkt)))
	})

	t.Run("refused for another key", func(t *testing.T) {
		var ae *apiauth.AuthError
		require.ErrorAs(t, validate(confirmFor(newDPoPKey(t).jkt)), &ae)
		assert.Equal(t, "invalid_token", ae.Code)
	})
}

// Keycloak's introspection response carries exp and iat, and TokenInfo
// reports them for a resource server that validates by introspection.
func TestKeycloakValidateBearer_IntrospectionTimes(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)
	tok := getClientCredentialsToken(t, cfg.TokenEndpoint, confidentialClientID, confidentialClientSecret)
	claims := parseJWTClaims(t, tok.AccessToken)
	mw := &apiauth.APIMiddleware{Introspection: &apiauth.IntrospectionValidator{
		IntrospectionURL: cfg.IntrospectionEndpoint,
		ClientID:         confidentialClientID,
		ClientSecret:     confidentialClientSecret,
	}}

	resp, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: tok.AccessToken})

	require.NoError(t, err)
	assert.Equal(t, "introspection", resp.Info.AuthType)
	assert.True(t, resp.Info.ExpiresAt.Equal(claimTime(t, claims, "exp")), "ExpiresAt = %v", resp.Info.ExpiresAt)
	assert.True(t, resp.Info.IssuedAt.Equal(claimTime(t, claims, "iat")), "IssuedAt = %v", resp.Info.IssuedAt)
}
