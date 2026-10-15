package apiauth_test

// Proof checks found missing or untested by the issue 88 DPoP audit. Each is
// a requirement of RFC 9449 §4.3 or of the FAPI 2.0 Security Profile that a
// weaker validator would let through.
//
// References:
//   - RFC 9449 §4.3 (https://www.rfc-editor.org/rfc/rfc9449#section-4.3)
//   - RFC 9449 §11.1 (https://www.rfc-editor.org/rfc/rfc9449#section-11.1)
//   - FAPI 2.0 Security Profile §5.3.2.1 and §5.4.1 (https://openid.net/specs/fapi-security-profile-2_0-final.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

// FAPI 2.0 §5.4.1 requires RSA keys of at least 2048 bits. A short key in a
// proof would let a client bind tokens to a key that can be factored.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
func TestDPoPProof_RejectsShortRSAKey(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err = validateProof(t, v, newProof(t, short, proofOpts{}))

	assertInvalidProof(t, err)
}

func TestDPoPProof_AcceptsPS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	resp, err := validateProof(t, v, newProof(t, key, proofOpts{signMethod: jwt.SigningMethodPS256}))

	require.NoError(t, err)
	assert.NotEmpty(t, resp.JKT)
}

// FAPI 2.0 §5.4.1 allows PS256, ES256 and EdDSA, so the preset refuses RS256.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
func TestDPoPProof_FAPIAlgsRefuseRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{AllowedAlgs: apiauth.FAPIDPoPAlgs()})

	_, err = validateProof(t, v, newProof(t, key, proofOpts{signMethod: jwt.SigningMethodRS256}))
	assertInvalidProof(t, err)

	_, err = validateProof(t, v, newProof(t, key, proofOpts{signMethod: jwt.SigningMethodPS256}))
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"ES256", "PS256"}, v.SigningAlgValuesSupported())
}

// A jti is remembered for the whole acceptance window, so an unbounded one
// lets a client make the replay store hold arbitrarily large keys.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-11.1
func TestDPoPProof_RejectsOversizedJTI(t *testing.T) {
	_, sign := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, sign(proofOpts{jti: strings.Repeat("j", 257)}))
	assertInvalidProof(t, err)

	_, err = validateProof(t, v, sign(proofOpts{jti: strings.Repeat("j", 256)}))
	assert.NoError(t, err)
}

// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3 (item 4)
func TestDPoPProof_RejectsMissingRequiredClaims(t *testing.T) {
	_, sign := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})
	for name, opts := range map[string]proofOpts{
		"htm": {omitHTM: true},
		"htu": {omitHTU: true},
		"iat": {omitIAT: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validateProof(t, v, sign(opts))
			assertInvalidProof(t, err)
		})
	}
}

// FAPI 2.0 §5.3.2.1 item 13: accept an iat up to 10 seconds in the future,
// and reject one more than 60 seconds ahead.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
func TestDPoPProof_FAPIFutureIATEdges(t *testing.T) {
	_, sign := newProofSigner(t)
	now := time.Now()
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{Now: func() time.Time { return now }})

	_, err := validateProof(t, v, sign(proofOpts{iat: now.Add(10 * time.Second)}))
	assert.NoError(t, err, "10s ahead must be accepted")

	_, err = validateProof(t, v, sign(proofOpts{iat: now.Add(61 * time.Second)}))
	assertInvalidProof(t, err)
}

// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3 (item 2)
func TestDPoPProof_ConfirmResourceRejectsMultipleHeaders(t *testing.T) {
	_, proofA := newProofSigner(t)
	_, proofB := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: "https://rs.example.com"})
	token := "access-token"

	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	for _, sign := range []func(proofOpts) string{proofA, proofB} {
		req.Header.Add("DPoP", sign(proofOpts{method: http.MethodGet, url: "https://rs.example.com/data", ath: athFor(token)}))
	}
	cnf, err := v.ConfirmResource(context.Background(), req, token)

	assertInvalidProof(t, err)
	assert.Nil(t, cnf)
}
