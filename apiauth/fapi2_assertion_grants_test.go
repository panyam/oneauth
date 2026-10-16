package apiauth_test

// Under FAPI 2.0 every token request authenticates the client, including
// the assertion grants. jwt-bearer and token-exchange used to look the client
// up by the request's client_id, so a request that sent none skipped client
// authentication entirely.
//
// References:
//   - FAPI 2.0 Security Profile §5.3.2.1, §5.3.3.4 (https://openid.net/specs/fapi-security-profile-2_0-final.html)
//   - RFC 7523 §3 (https://www.rfc-editor.org/rfc/rfc7523#section-3)
//   - CWE-306 (https://cwe.mitre.org/data/definitions/306.html)
//   - See: https://github.com/panyam/oneauth/issues/434

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

const fapiIdP = "https://idp.example.com"

// newFAPIAssertionFixture trusts one upstream IdP for jwt-bearer and
// token-exchange, and returns a signer for that IdP's assertions.
func newFAPIAssertionFixture(t *testing.T, fapi2 bool) (*fapiFixture, func() string) {
	t.Helper()
	idpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f := newFAPIFixtureWith(t, fapi2, func(c *apiauth.OneAuthConfig) {
		c.TrustedAssertionIssuers = []apiauth.TrustedAssertionIssuer{{
			Issuer: fapiIdP, PublicKey: &idpKey.PublicKey, Audiences: []string{fapiIssuer}, AcceptedAlgorithms: []string{"ES256"},
		}}
	})
	idpAssertion := func() string {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": fapiIdP, "sub": "alice", "aud": fapiIssuer,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		}).SignedString(idpKey)
		require.NoError(t, err)
		return tok
	}
	return f, idpAssertion
}

func withClientAssertion(form url.Values, assertion string) url.Values {
	form.Set("client_assertion_type", apiauth.ClientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)
	return form
}

func TestFAPI2_JwtBearerWithoutClientIDAuthenticatesTheClient(t *testing.T) {
	f, idp := newFAPIAssertionFixture(t, true)
	grant := func() url.Values {
		return url.Values{"grant_type": {apiauth.JwtBearerGrantType}, "assertion": {idp()}}
	}

	rr := f.post(t, fapiReq{form: grant(), proof: true})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "no client authentication at all: %s", rr.Body.String())

	rr = f.post(t, fapiReq{form: withClientAssertion(grant(), f.assertion(t, fapiIssuer)), proof: true})
	assert.Equal(t, http.StatusOK, rr.Code, "private_key_jwt without client_id names the client by iss: %s", rr.Body.String())
}

func TestFAPI2_TokenExchangeWithoutClientIDAuthenticatesTheClient(t *testing.T) {
	f, idp := newFAPIAssertionFixture(t, true)
	grant := func() url.Values {
		return url.Values{"grant_type": {apiauth.TokenExchangeGrantType}, "subject_token": {idp()}, "subject_token_type": {apiauth.TokenTypeJWT}}
	}

	rr := f.post(t, fapiReq{form: grant(), proof: true})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "no client authentication at all: %s", rr.Body.String())

	rr = f.post(t, fapiReq{form: withClientAssertion(grant(), f.assertion(t, fapiIssuer)), proof: true})
	assert.Equal(t, http.StatusOK, rr.Code, "private_key_jwt without client_id names the client by iss: %s", rr.Body.String())
}

// Outside FAPI the RFC 7523 §3 assertion-only path stays open: the
// assertion is the grant, and client authentication is optional.
func TestJwtBearer_AssertionOnlyStillWorksWithoutFAPI(t *testing.T) {
	f, idp := newFAPIAssertionFixture(t, false)
	rr := f.post(t, fapiReq{form: url.Values{"grant_type": {apiauth.JwtBearerGrantType}, "assertion": {idp()}}})
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}
