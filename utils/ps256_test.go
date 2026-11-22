package utils_test

// PS256 (RSASSA-PSS with SHA-256, RFC 7518 §3.5) as a signing algorithm
// for an RSA key (issue 330). FAPI 2.0 §5.4 allows PS256 and ES256, not
// RS256.
//
// See: https://www.rfc-editor.org/rfc/rfc7518#section-3.5
// See: https://github.com/panyam/oneauth/issues/330

import (
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPS256_IsAsymmetric(t *testing.T) {
	assert.True(t, utils.IsAsymmetricAlg("PS256"))
}

func TestPS256_SigningMethod(t *testing.T) {
	m, err := utils.SigningMethodForAlg("PS256")
	require.NoError(t, err)
	assert.Equal(t, jwt.SigningMethodPS256, m)
}

// A PS256 key is stored as RSA PEM, like an RS256 one.
func TestPS256_DecodeVerifyKey(t *testing.T) {
	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	got, err := utils.DecodeVerifyKey(pubPEM, "PS256")
	require.NoError(t, err)
	_, ok := got.(*rsa.PublicKey)
	assert.True(t, ok, "got %T", got)

	_, ecPEM, err := utils.GenerateECDSAKeyPair()
	require.NoError(t, err)
	_, err = utils.DecodeVerifyKey(ecPEM, "PS256")
	assert.Error(t, err, "PS256 needs an RSA key")
}

// The kid is the key's RFC 7638 thumbprint, which leaves out the
// algorithm, so one RSA key has the same kid under RS256 and PS256.
func TestPS256_KidIsTheThumbprint(t *testing.T) {
	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	rs, err := utils.ComputeKid(pubPEM, "RS256")
	require.NoError(t, err)
	ps, err := utils.ComputeKid(pubPEM, "PS256")
	require.NoError(t, err)
	assert.Equal(t, rs, ps)
}
