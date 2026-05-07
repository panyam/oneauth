// Tests for RFC 8693 — OAuth 2.0 Token Exchange. Verifies that the AS
// accepts grant_type=urn:ietf:params:oauth:grant-type:token-exchange
// when the subject_token (a signed JWT in this Phase 1 implementation)
// is issued by a trusted IdP and meets the §3 claim requirements;
// returns the RFC 8693 §2.2 response shape with issued_token_type.
//
// See:
//   - RFC 8693:        https://www.rfc-editor.org/rfc/rfc8693
//   - RFC 7523 §3:     https://www.rfc-editor.org/rfc/rfc7523#section-3
//   - oneauth issue 118
//   - mcpkit issue 381 (paired conformance gap)
package apiauth_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
)

// reuses jwtBearerTestEnv + mintAssertion + postForm from
// jwt_bearer_grant_test.go — same trusted-issuer setup.

// TestTokenExchangeGrant_HappyPath — properly-signed subject_token (JWT)
// from a trusted IdP yields a 200 + access_token + issued_token_type.
func TestTokenExchangeGrant_HappyPath(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	subjectToken := env.mintAssertion(t, nil)

	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", apiauth.TokenTypeJWT)
	form.Set("scope", "read")

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, body["access_token"])
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Equal(t, apiauth.TokenTypeAccessToken, body["issued_token_type"],
		"RFC 8693 §2.2 REQUIRES issued_token_type in token-exchange responses")
}

// TestTokenExchangeGrant_DefaultRequestedTokenType — when
// requested_token_type is omitted, it defaults to access_token per
// RFC 8693 §2.1.
func TestTokenExchangeGrant_DefaultRequestedTokenType(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	subjectToken := env.mintAssertion(t, nil)

	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", apiauth.TokenTypeJWT)
	// requested_token_type intentionally omitted.

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, apiauth.TokenTypeAccessToken, body["issued_token_type"])
}

// TestTokenExchangeGrant_NoTrustedIssuersConfigured — without
// TrustedAssertionIssuers, the grant returns unsupported_grant_type.
func TestTokenExchangeGrant_NoTrustedIssuersConfigured(t *testing.T) {
	a := &apiauth.APIAuth{
		JWTSecretKey: "test",
		JWTIssuer:    "oneauth-test",
	}
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", "irrelevant")
	form.Set("subject_token_type", apiauth.TokenTypeJWT)

	status, body := postForm(t, a, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "unsupported_grant_type", body["error"])
}

// TestTokenExchangeGrant_MissingSubjectToken — required param.
func TestTokenExchangeGrant_MissingSubjectToken(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token_type", apiauth.TokenTypeJWT)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_request", body["error"])
	assert.Contains(t, body["error_description"], "subject_token")
}

// TestTokenExchangeGrant_MissingSubjectTokenType — required param.
func TestTokenExchangeGrant_MissingSubjectTokenType(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	subjectToken := env.mintAssertion(t, nil)
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_request", body["error"])
	assert.Contains(t, body["error_description"], "subject_token_type")
}

// TestTokenExchangeGrant_UnsupportedSubjectTokenType — Phase 1 only
// handles JWT; other types return invalid_request.
func TestTokenExchangeGrant_UnsupportedSubjectTokenType(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	subjectToken := env.mintAssertion(t, nil)

	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", apiauth.TokenTypeSAML2)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_request", body["error"])
}

// TestTokenExchangeGrant_UnsupportedRequestedTokenType — Phase 1 only
// issues access_token; other types return invalid_request.
func TestTokenExchangeGrant_UnsupportedRequestedTokenType(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	subjectToken := env.mintAssertion(t, nil)

	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", apiauth.TokenTypeJWT)
	form.Set("requested_token_type", apiauth.TokenTypeIDToken)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_request", body["error"])
}

// TestTokenExchangeGrant_UntrustedIssuer — same iss-validation behavior
// as jwt-bearer grant (shared validateAssertion).
func TestTokenExchangeGrant_UntrustedIssuer(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	subjectToken := env.mintAssertion(t, jwt.MapClaims{
		"iss": "https://malicious-idp.example.com",
	})
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", apiauth.TokenTypeJWT)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestTokenExchangeGrant_ExpiredSubjectToken — same exp-validation
// behavior.
func TestTokenExchangeGrant_ExpiredSubjectToken(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	subjectToken := env.mintAssertion(t, jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"nbf": time.Now().Add(-2 * time.Hour).Unix(),
	})
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", apiauth.TokenTypeJWT)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestTokenExchangeGrant_AudienceParamAcceptedAdvisory — RFC 8693
// audience param is parsed but currently advisory; the grant succeeds
// regardless. (Future commits will bind it into the issued aud claim.)
func TestTokenExchangeGrant_AudienceParamAcceptedAdvisory(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	subjectToken := env.mintAssertion(t, nil)

	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", apiauth.TokenTypeJWT)
	form.Set("audience", "https://downstream.example.com")
	form.Set("resource", "https://downstream.example.com/api")

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusOK, status,
		"audience/resource params MUST be accepted (advisory in Phase 1)")
	assert.NotEmpty(t, body["access_token"])
}
