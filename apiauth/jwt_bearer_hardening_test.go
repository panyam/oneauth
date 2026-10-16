package apiauth_test

// jwt-bearer assertions, issue 88's "Token Security" walk: RFC 7523 §3
// makes exp and aud mandatory, and an assertion carrying a jti is spent
// once it's used.
//
// References:
//   - RFC 7523 §3 (https://www.rfc-editor.org/rfc/rfc7523#section-3)
//   - CWE-294 (https://cwe.mitre.org/data/definitions/294.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

func jwtBearerForm(assertion string) url.Values {
	return url.Values{"grant_type": {apiauth.JwtBearerGrantType}, "assertion": {assertion}, "scope": {"read"}}
}

// See: https://www.rfc-editor.org/rfc/rfc7523#section-3
func TestJwtBearerHardening_ExpIsRequired(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	status, body := postForm(t, env.apiAuth, jwtBearerForm(env.mintAssertion(t, jwt.MapClaims{"exp": nil})))
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

// With no audience to compare against, an assertion minted for some other
// AS would be accepted here.
//
// See: https://www.rfc-editor.org/rfc/rfc7523#section-3
func TestJwtBearerHardening_NoAudienceConfiguredRefuses(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	issuers := []apiauth.TrustedAssertionIssuer{{Issuer: env.idpIssuer, PublicKey: &env.idpKey.PublicKey, AcceptedAlgorithms: []string{"RS256"}}}
	_, _, err := apiauth.ValidateAssertion(issuers, "", "", env.mintAssertion(t, jwt.MapClaims{"aud": "https://some-other-as.example"}))
	assert.Error(t, err)
}

// See: https://www.rfc-editor.org/rfc/rfc7523#section-3
// See: https://cwe.mitre.org/data/definitions/294.html
func TestJwtBearerHardening_AssertionWithJTIIsSingleUse(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	assertion := env.mintAssertion(t, jwt.MapClaims{"jti": "assertion-1"})

	status, _ := postForm(t, env.apiAuth, jwtBearerForm(assertion))
	require.Equal(t, http.StatusOK, status)

	status, body := postForm(t, env.apiAuth, jwtBearerForm(assertion))
	assert.Equal(t, http.StatusBadRequest, status, "the same assertion a second time")
	assert.Equal(t, "invalid_grant", body["error"])

	// A different jti from the same issuer is a different assertion.
	status, _ = postForm(t, env.apiAuth, jwtBearerForm(env.mintAssertion(t, jwt.MapClaims{"jti": "assertion-2"})))
	assert.Equal(t, http.StatusOK, status)
}
