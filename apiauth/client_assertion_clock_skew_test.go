package apiauth_test

// Clock-skew tolerance on client assertions. FAPI 2.0 asks the server to
// accept an iat or nbf up to 10 seconds ahead of its clock and to refuse
// one more than 60 seconds ahead.
//
// References:
//   - FAPI 2.0 Security Profile §5.3.2.1 (https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1)
//   - RFC 7519 §4.1.5, §4.1.6 (https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5)
//   - See: https://github.com/panyam/oneauth/issues/439

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
)

const skewAudience = "https://as.example.com"

// authenticateWithTimes signs an HS256 assertion with the given claim
// times (a zero time leaves the claim out) and runs it through the
// authenticator.
func authenticateWithTimes(t *testing.T, iat, nbf, exp time.Time) error {
	t.Helper()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	ks := keys.NewInMemoryKeyStore()
	_, err = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "skew-app", Key: secret, Algorithm: "HS256"}})
	require.NoError(t, err)

	claims := jwt.MapClaims{"iss": "skew-app", "sub": "skew-app", "aud": skewAudience, "jti": rand.Text(), "exp": exp.Unix()}
	if !iat.IsZero() {
		claims["iat"] = iat.Unix()
	}
	if !nbf.IsZero() {
		claims["nbf"] = nbf.Unix()
	}
	assertion, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	require.NoError(t, err)

	_, err = apiauth.NewClientAuthenticator(ks).AuthenticateClient(context.Background(), &apiauth.AuthenticateClientRequest{
		ClientAssertionType: apiauth.ClientAssertionTypeJWTBearer,
		ClientAssertion:     assertion,
		Audiences:           []string{skewAudience},
	})
	return err
}

// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
func TestClientAssertion_AcceptsIatAndNbfSlightlyAhead(t *testing.T) {
	ahead := time.Now().Add(8 * time.Second)
	assert.NoError(t, authenticateWithTimes(t, ahead, ahead, ahead.Add(time.Minute)))
}

// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
func TestClientAssertion_RefusesIatFarAhead(t *testing.T) {
	ahead := time.Now().Add(70 * time.Second)
	assert.Error(t, authenticateWithTimes(t, ahead, time.Time{}, ahead.Add(time.Minute)))
}

// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
func TestClientAssertion_RefusesNbfFarAhead(t *testing.T) {
	now := time.Now()
	assert.Error(t, authenticateWithTimes(t, time.Time{}, now.Add(70*time.Second), now.Add(2*time.Minute)))
}

// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
func TestClientAssertion_StillRefusesAnExpiredAssertion(t *testing.T) {
	now := time.Now()
	assert.Error(t, authenticateWithTimes(t, now.Add(-6*time.Minute), time.Time{}, now.Add(-5*time.Minute)))
}
