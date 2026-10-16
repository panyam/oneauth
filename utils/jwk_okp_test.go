package utils

// Ed25519 keys as OKP JWKs (RFC 8037), which EdDSA DPoP proofs carry. The
// key and thumbprint are RFC 8037 Appendix A.2 and A.3.
//
// See: https://www.rfc-editor.org/rfc/rfc8037#appendix-A.3

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rfc8037X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"

func TestJWKToPublicKey_Ed25519(t *testing.T) {
	pub, _, err := JWKToPublicKey(JWK{Kty: "OKP", Crv: "Ed25519", X: rfc8037X})
	require.NoError(t, err)
	edPub, ok := pub.(ed25519.PublicKey)
	require.True(t, ok, "got %T", pub)
	assert.Equal(t, rfc8037X, base64.RawURLEncoding.EncodeToString(edPub))
}

func TestJWKToPublicKey_RejectsOtherOKPKeys(t *testing.T) {
	for name, jwk := range map[string]JWK{
		"Ed448":           {Kty: "OKP", Crv: "Ed448", X: rfc8037X},
		"X25519":          {Kty: "OKP", Crv: "X25519", X: rfc8037X},
		"short x":         {Kty: "OKP", Crv: "Ed25519", X: rfc8037X[:20]},
		"x not base64url": {Kty: "OKP", Crv: "Ed25519", X: "!!!"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := JWKToPublicKey(jwk)
			assert.Error(t, err)
		})
	}
}

// See: https://www.rfc-editor.org/rfc/rfc8037#appendix-A.3
func TestComputeKid_Ed25519MatchesRFC8037(t *testing.T) {
	raw, err := base64.RawURLEncoding.DecodeString(rfc8037X)
	require.NoError(t, err)

	kid, err := ComputeKid(ed25519.PublicKey(raw), "EdDSA")
	require.NoError(t, err)
	assert.Equal(t, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", kid)
}

func TestEd25519PublicKeyToJWK_RoundTrips(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	back, _, err := JWKToPublicKey(Ed25519PublicKeyToJWK("", "EdDSA", pub))
	require.NoError(t, err)
	assert.Equal(t, pub, back)
}
