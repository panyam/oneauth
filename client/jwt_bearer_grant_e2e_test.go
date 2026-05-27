package client_test

// E2E coverage for AuthClient.JwtBearerGrant against the in-process
// OneAuth AS (testutil.TestAuthServer with TrustedAssertionIssuers
// wired up). Proves the SDK -> real AS path round-trips: AS verifies
// the assertion JWT, issues an access token, SDK decodes it into a
// usable ServerCredential.

import (
	"context"
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

func TestJwtBearerGrant_E2E_TrustedIssuerRoundTrip(t *testing.T) {
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
	assertion, err := tok.SignedString(idpKey)
	require.NoError(t, err)

	c := client.NewAuthClient(srv.URL(), nil,
		client.WithTokenEndpoint("/api/token"))
	cred, err := c.JwtBearerGrant(context.Background(), &client.JwtBearerGrantRequest{
		ClientID:  "demo-client",
		Assertion: assertion,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, cred.AccessToken, "AS MUST issue an access token for a trusted-issuer assertion")
}
