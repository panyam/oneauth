package apiauth_test

// Every ID token carries its own `jti` (issue 563). A relying party that
// takes the ID token as an RFC 7523 assertion, such as Keycloak's JWT
// Authorization Grant, refuses a replay by its jti, and needs one to do so.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7
// See: https://www.rfc-editor.org/rfc/rfc7523#section-3
// See: https://github.com/panyam/oneauth/issues/563

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

func TestOIDC_IDTokenCarriesAFreshJTI(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer, err := apiauth.NewJWTIDTokenIssuer(apiauth.JWTIDTokenIssuerConfig{
		SigningKey: key, SigningAlg: "ES256", Issuer: oidcIssuer,
	})
	require.NoError(t, err)

	jti := func() string {
		resp, err := issuer.CreateIDToken(context.Background(), &apiauth.CreateIDTokenRequest{
			Subject: "alice", ClientID: "client-1", Nonce: "n-1",
		})
		require.NoError(t, err)
		claims := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(resp.Token, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
		require.NoError(t, err)
		s, _ := claims["jti"].(string)
		return s
	}
	first, second := jti(), jti()
	assert.Regexp(t, `^[0-9a-f]{64}$`, first, "32 random bytes, hex encoded")
	assert.NotEqual(t, first, second, "two ID tokens from the same request get different jtis")
}
