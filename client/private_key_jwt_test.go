package client_test

// Client-side tests for the private_key_jwt assertion minter.
//
// References:
//   - RFC 7521 §4.2 (https://www.rfc-editor.org/rfc/rfc7521#section-4.2)
//   - RFC 7523 §2.2 (https://www.rfc-editor.org/rfc/rfc7523#section-2.2)
//   - OIDC Core §9  (https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
)

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

// TestMintClientAssertion_ClaimShape verifies the assertion carries
// every claim required by RFC 7523 §3 for client authentication and
// that those claims have the values the spec mandates.
func TestMintClientAssertion_ClaimShape(t *testing.T) {
	priv := newRSAKey(t)
	const clientID = "demo-client"
	const audience = "https://as.example.com/token"

	signed, err := client.MintClientAssertion(clientID, audience, client.ClientAssertionConfig{
		PrivateKey: priv,
		SigningAlg: "RS256",
		KeyID:      "key-1",
	})
	require.NoError(t, err)

	parsed, err := jwt.Parse(signed, func(t *jwt.Token) (any, error) { return &priv.PublicKey, nil })
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, clientID, claims["iss"], "iss MUST equal client_id")
	assert.Equal(t, clientID, claims["sub"], "sub MUST equal client_id")
	assert.Equal(t, audience, claims["aud"], "aud MUST equal target audience")
	assert.NotEmpty(t, claims["jti"], "jti MUST be present (replay protection)")
	assert.NotEmpty(t, claims["iat"], "iat SHOULD be present")
	assert.NotEmpty(t, claims["exp"], "exp MUST be present")

	// kid header — set when caller provides KeyID.
	assert.Equal(t, "key-1", parsed.Header["kid"], "kid header MUST round-trip")
}

// TestMintClientAssertion_DefaultLifetime — when Lifetime is unset, the
// minted assertion should expire ~60s in the future per OIDC Core §9
// recommendation. Allow a small window for clock skew between the
// computed exp and our test wall-clock.
func TestMintClientAssertion_DefaultLifetime(t *testing.T) {
	priv := newRSAKey(t)
	signed, err := client.MintClientAssertion("c", "aud", client.ClientAssertionConfig{
		PrivateKey: priv,
		SigningAlg: "RS256",
	})
	require.NoError(t, err)

	parsed, err := jwt.Parse(signed, func(t *jwt.Token) (any, error) { return &priv.PublicKey, nil })
	require.NoError(t, err)

	expDate, err := parsed.Claims.GetExpirationTime()
	require.NoError(t, err)
	require.NotNil(t, expDate)

	delta := time.Until(expDate.Time)
	assert.GreaterOrEqual(t, delta, 55*time.Second, "default lifetime ~ 60s")
	assert.LessOrEqual(t, delta, 65*time.Second, "default lifetime ~ 60s")
}

// TestMintClientAssertion_FreshJTIPerCall — the jti claim MUST be
// unique per assertion (RFC 7523 §3 item 7) so the AS can replay-block.
// Two assertions minted back-to-back must have different jti values.
func TestMintClientAssertion_FreshJTIPerCall(t *testing.T) {
	priv := newRSAKey(t)
	a, err := client.MintClientAssertion("c", "aud", client.ClientAssertionConfig{
		PrivateKey: priv,
		SigningAlg: "RS256",
	})
	require.NoError(t, err)
	b, err := client.MintClientAssertion("c", "aud", client.ClientAssertionConfig{
		PrivateKey: priv,
		SigningAlg: "RS256",
	})
	require.NoError(t, err)

	parseJTI := func(s string) string {
		tok, err := jwt.Parse(s, func(t *jwt.Token) (any, error) { return &priv.PublicKey, nil })
		require.NoError(t, err)
		c, _ := tok.Claims.(jwt.MapClaims)
		jti, _ := c["jti"].(string)
		return jti
	}
	assert.NotEqual(t, parseJTI(a), parseJTI(b), "jti MUST differ between assertions")
}

// TestMintClientAssertion_RequiresInputs — minimal-viable validation
// that callers don't trigger nil-derefs on bad input. These are sanity
// checks, not security boundaries.
func TestMintClientAssertion_RequiresInputs(t *testing.T) {
	priv := newRSAKey(t)
	cfg := client.ClientAssertionConfig{PrivateKey: priv, SigningAlg: "RS256"}

	cases := []struct {
		name          string
		clientID, aud string
		cfg           client.ClientAssertionConfig
	}{
		{name: "missing clientID", aud: "x", cfg: cfg},
		{name: "missing audience", clientID: "x", cfg: cfg},
		{name: "missing PrivateKey", clientID: "x", aud: "x", cfg: client.ClientAssertionConfig{SigningAlg: "RS256"}},
		{name: "missing SigningAlg", clientID: "x", aud: "x", cfg: client.ClientAssertionConfig{PrivateKey: priv}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.MintClientAssertion(tc.clientID, tc.aud, tc.cfg)
			assert.Error(t, err)
		})
	}
}
