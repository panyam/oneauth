package client

// Ed25519 DPoP keys in the SDK. FAPI 2.0 §5.4.1 allows EdDSA alongside ES256
// and PS256, and an Ed25519 signature is cheaper still than P-256.
//
// See: https://www.rfc-editor.org/rfc/rfc8037
// See: https://github.com/panyam/oneauth/issues/395

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/utils"
)

func TestEd25519DPoPKey_ProofVerifiesAtTheServer(t *testing.T) {
	key, err := NewEd25519DPoPKey()
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", key.Algorithm())

	proof, err := key.Proof("POST", "https://as.example.com/token", "")
	require.NoError(t, err)
	parsed, _, err := jwt.NewParser().ParseUnverified(proof, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", parsed.Header["alg"])
	jwkHeader, _ := parsed.Header["jwk"].(map[string]any)
	assert.Equal(t, "OKP", jwkHeader["kty"])
	assert.Equal(t, "Ed25519", jwkHeader["crv"])

	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})
	resp, err := v.Validate(context.Background(), &apiauth.DPoPProofRequest{
		Proof: proof, Method: "POST", URL: "https://as.example.com/token",
	})
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), resp.JKT, "client and server agree on the thumbprint")
}

func TestNewDPoPKeyFromEd25519_KeepsTheKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	key, err := NewDPoPKeyFromEd25519(priv)
	require.NoError(t, err)

	want, err := utils.ComputeKid(pub, "EdDSA")
	require.NoError(t, err)
	assert.Equal(t, want, key.Thumbprint())

	_, err = NewDPoPKeyFromEd25519(nil)
	assert.Error(t, err)
}
