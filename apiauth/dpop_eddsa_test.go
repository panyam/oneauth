package apiauth_test

// EdDSA (Ed25519) DPoP proofs. FAPI 2.0 §5.4.1 allows PS256, ES256 and
// EdDSA, and RFC 9449 leaves the algorithm to the server. The thumbprint
// that goes in cnf.jkt is the RFC 8037 OKP one.
//
// References:
//   - RFC 8037 (https://www.rfc-editor.org/rfc/rfc8037)
//   - FAPI 2.0 Security Profile §5.4.1 (https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1)
//   - See: https://github.com/panyam/oneauth/issues/395

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/utils"
)

func newEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv
}

func TestDPoPEdDSA_DefaultValidatorAccepts(t *testing.T) {
	key := newEd25519Key(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	resp, err := validateProof(t, v, newProof(t, key, proofOpts{}))

	require.NoError(t, err)
	want, err := utils.ComputeKid(key.Public(), "EdDSA")
	require.NoError(t, err)
	assert.Equal(t, want, resp.JKT)
	assert.Contains(t, v.SigningAlgValuesSupported(), "EdDSA")
}

// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
func TestDPoPEdDSA_FAPIPresetIncludesEdDSA(t *testing.T) {
	algs := apiauth.FAPIDPoPAlgs()
	assert.ElementsMatch(t, []string{"PS256", "ES256", "EdDSA"}, algs)

	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{AllowedAlgs: algs})
	_, err := validateProof(t, v, newProof(t, newEd25519Key(t), proofOpts{}))
	assert.NoError(t, err)
}

// An EdDSA proof whose jwk claims to be an Ed25519 key but carries the
// private half is refused like any other key type.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3 (check 8)
func TestDPoPEdDSA_RefusesPrivateKeyInJWK(t *testing.T) {
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})
	_, err := validateProof(t, v, newProof(t, newEd25519Key(t), proofOpts{privateJWK: true}))
	assert.Error(t, err)
}

// A validator that doesn't list EdDSA refuses it, so a deployment can still
// leave it out.
func TestDPoPEdDSA_NotAcceptedWhenNotAllowed(t *testing.T) {
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{AllowedAlgs: []string{"ES256"}})
	_, err := validateProof(t, v, newProof(t, newEd25519Key(t), proofOpts{}))
	assert.Error(t, err)
}

// The token endpoint binds a token to an Ed25519 key.
func TestDPoPEdDSA_TokenEndpointBindsTheKey(t *testing.T) {
	fx := newDPoPFixture(t, true, nil)
	key := newEd25519Key(t)

	rr := postWithProof(t, fx, clientCredentialsForm(), newProof(t, key, proofOpts{url: dpopTokenEndpointURL, method: http.MethodPost}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	want, err := utils.ComputeKid(key.Public(), "EdDSA")
	require.NoError(t, err)
	assertBoundTo(t, decodeJSON(t, rr), want)
}
