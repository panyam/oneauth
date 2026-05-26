package client_test

// E2E coverage for AuthClient.TokenExchange against the in-process
// OneAuth AS. Validates the SDK -> real AS conversation: a signed JWT
// from a trusted upstream issuer is exchanged at the token endpoint
// and the SDK decodes the issued_token_type-bearing response.

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/testutil"
)

func TestTokenExchange_E2E_JWTSubjectToken(t *testing.T) {
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const idpIssuer = "https://corp-idp.example.com"
	const asAudience = "oneauth-test-as"

	srv := testutil.NewTestAuthServer(t,
		testutil.WithAudience(asAudience),
		testutil.WithTrustedAssertionIssuers([]apiauth.TrustedAssertionIssuer{{
			Issuer:             idpIssuer,
			PublicKey:          &idpKey.PublicKey,
			Audiences:          []string{asAudience},
			AcceptedAlgorithms: []string{"RS256"},
		}}),
	)
	defer srv.Close()

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": idpIssuer,
		"sub": "alice",
		"aud": asAudience,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-1 * time.Second).Unix(),
	})
	subjectToken, err := tok.SignedString(idpKey)
	require.NoError(t, err)

	c := client.NewAuthClient(srv.URL(), nil,
		client.WithTokenEndpoint("/api/token"))
	resp, err := c.TokenExchange(&client.TokenExchangeRequest{
		ClientID:         "demo-client",
		SubjectToken:     subjectToken,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken, "AS MUST issue an access token in exchange")
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", resp.IssuedTokenType,
		"issued_token_type MUST round-trip in the RFC 8693 response")
	assert.Equal(t, "Bearer", resp.TokenType)
}
