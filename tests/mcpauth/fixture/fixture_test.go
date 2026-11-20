package fixture

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer   = "https://as.example"
	testAudience = "https://mcp.example/mcp"
)

// Each bad token must verify against the AS key and fail exactly one claim
// check, or the conformance check it feeds tests the wrong thing: a token
// the resource server refuses for its signature says nothing about how it
// handles exp, aud or iss.
func TestBadTokens_EachFailsOnlyItsOwnClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := apiauth.NewJWTIssuer(apiauth.JWTIssuerConfig{SigningKey: key, SigningAlg: "RS256", Issuer: testIssuer, Audience: testAudience})
	valid, err := issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "client-1", Scopes: []string{"read"}})
	require.NoError(t, err)

	expired, wrongAud, wrongIss, err := BadTokens(valid.Token, key, "RS256")
	require.NoError(t, err)

	validator := apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{SigningKey: &key.PublicKey, SigningAlg: "RS256", Issuer: testIssuer, Audience: testAudience})
	check := func(tok string) error {
		_, err := validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: tok})
		return err
	}
	require.NoError(t, check(valid.Token), "the token the variants start from is valid")
	assert.ErrorContains(t, check(expired), "expired")
	assert.ErrorContains(t, check(wrongAud), "audience")
	assert.ErrorContains(t, check(wrongIss), "issuer")

	header, _, err := parse(valid.Token)
	require.NoError(t, err)
	for _, tok := range []string{expired, wrongAud, wrongIss} {
		h, _, err := parse(tok)
		require.NoError(t, err)
		assert.Equal(t, header["kid"], h["kid"], "the JWKS lookup finds the AS key")
	}
}

func TestLoadKey_ReadsRSAAndEC(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pem, err := utils.EncodePrivateKeyPEM(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "k.pem")
	require.NoError(t, os.WriteFile(path, pem, 0o600))
	_, alg, err := LoadKey(path)
	require.NoError(t, err)
	assert.Equal(t, "RS256", alg)
}

// The upstream assertion names the trusted IdP as iss and the AS as aud,
// and verifies with the IdP's key, which is all the AS checks.
func TestUpstreamAssertion_VerifiesAsTheIdP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tok, err := UpstreamAssertion(key, "RS256", "https://idp.test", "https://as.test", "alice")
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithIssuer("https://idp.test"), jwt.WithAudience("https://as.test"), jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err)
	assert.Equal(t, "alice", claims["sub"])
	assert.NotEmpty(t, claims["jti"])
}
