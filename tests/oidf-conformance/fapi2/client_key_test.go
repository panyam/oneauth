// Tests for the plan's client keys: the PS256 key the first client
// registers, and its JWKs (issue 558).
package fapi2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// See: https://www.rfc-editor.org/rfc/rfc7638#section-3.1
func TestClientKey_RSAThumbprintMatchesRFC7638Example(t *testing.T) {
	n, err := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	require.NoError(t, err)
	k := ClientKey{Alg: "PS256", rsa: &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}}}
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", k.thumbprint())
}

// The harness rebuilds the key from the private JWK and signs with it, so
// every member has to decode back to a working key.
func TestClientKey_RSAPrivateJWKRoundTrips(t *testing.T) {
	k, err := NewRSAClientKey()
	require.NoError(t, err)
	j := k.PrivateJWK()
	assert.Equal(t, "RSA", j["kty"])
	assert.Equal(t, "PS256", j["alg"])
	assert.Equal(t, "AQAB", j["e"])
	assert.Equal(t, k.KeyID, j["kid"])
	assert.Equal(t, k.thumbprint(), j["kid"])

	num := func(m string) *big.Int {
		b, err := base64.RawURLEncoding.DecodeString(j[m])
		require.NoError(t, err, m)
		return new(big.Int).SetBytes(b)
	}
	rebuilt := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: num("n"), E: int(num("e").Int64())},
		D:         num("d"),
		Primes:    []*big.Int{num("p"), num("q")},
	}
	require.NoError(t, rebuilt.Validate())
	rebuilt.Precompute()
	assert.Equal(t, 0, rebuilt.Precomputed.Dp.Cmp(num("dp")))
	assert.Equal(t, 0, rebuilt.Precomputed.Dq.Cmp(num("dq")))
	assert.Equal(t, 0, rebuilt.Precomputed.Qinv.Cmp(num("qi")))
	assert.Equal(t, 2048, rebuilt.N.BitLen())

	digest := sha256.Sum256([]byte("assertion"))
	sig, err := rsa.SignPSS(rand.Reader, rebuilt, crypto.SHA256, digest[:], nil)
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPSS(&k.rsa.PublicKey, crypto.SHA256, digest[:], sig, nil))

	pub := k.PublicJWK()
	for _, m := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		assert.NotContains(t, pub, m)
	}
}

func TestClientKey_PlanClientsUseBothAlgorithms(t *testing.T) {
	k0, err := clientKey(0)
	require.NoError(t, err)
	k1, err := clientKey(1)
	require.NoError(t, err)
	assert.Equal(t, "PS256", k0.Alg)
	assert.Equal(t, "ES256", k1.Alg)
	assert.Equal(t, "EC", k1.PrivateJWK()["kty"])
	assert.NotEmpty(t, k1.PrivateJWK()["d"])
}
