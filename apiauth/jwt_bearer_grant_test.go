// Tests for RFC 7523 §2.1 — JWT Bearer authorization grant. Verifies
// that the AS accepts grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
// when the assertion is signed by a trusted issuer and meets the §3
// claim requirements; rejects with invalid_grant otherwise.
//
// See:
//   - RFC 7523 §2.1: https://www.rfc-editor.org/rfc/rfc7523#section-2.1
//   - oneauth issue 181
//   - mcpkit issue 381 (paired conformance gap)
package apiauth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwtBearerTestEnv bundles the AS-under-test plus the trusted IdP's
// signing key so individual cases can mint freshly-claimed assertions.
type jwtBearerTestEnv struct {
	apiAuth    *apiauth.APIAuth
	idpKey     *rsa.PrivateKey
	idpIssuer  string
	asAudience string
}

func newJwtBearerTestEnv(t *testing.T) *jwtBearerTestEnv {
	t.Helper()

	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	asAudience := "https://oneauth-test/api/token"
	idpIssuer := "https://corp-idp.example.com"

	apiAuth := &apiauth.APIAuth{
		JWTSecretKey: "test-secret-key-for-testing-only",
		JWTIssuer:    "oneauth-test",
		JWTAudience:  asAudience,
		TrustedAssertionIssuers: []apiauth.TrustedAssertionIssuer{{
			Issuer:             idpIssuer,
			PublicKey:          &idpKey.PublicKey,
			Audiences:          []string{asAudience},
			AcceptedAlgorithms: []string{"RS256"},
		}},
	}

	return &jwtBearerTestEnv{
		apiAuth:    apiAuth,
		idpKey:     idpKey,
		idpIssuer:  idpIssuer,
		asAudience: asAudience,
	}
}

// mintAssertion signs a JWT with the test IdP's private key. Caller
// supplies any claim overrides; defaults populate a valid assertion.
// A nil value in overrides deletes the corresponding default claim.
func (e *jwtBearerTestEnv) mintAssertion(t *testing.T, overrides jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": e.idpIssuer,
		"sub": "alice@corp.example.com",
		"aud": e.asAudience,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-1 * time.Second).Unix(),
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(e.idpKey)
	require.NoError(t, err)
	return signed
}

// postForm sends a form-encoded token request and returns the HTTP
// status + decoded JSON body. Distinct helper from
// client_credentials_test.go's postTokenRequest (which takes a JSON
// string) to avoid the name collision while keeping each grant test
// file self-contained.
func postForm(
	t *testing.T,
	a *apiauth.APIAuth,
	form url.Values,
) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, req)
	var body map[string]any
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
	}
	return rr.Code, body
}

// TestJwtBearerGrant_HappyPath — properly-signed assertion with valid
// claims yields a 200 + access_token.
func TestJwtBearerGrant_HappyPath(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	assertion := env.mintAssertion(t, nil)

	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", assertion)
	form.Set("scope", "read")

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusOK, status, "happy path MUST return 200")
	assert.NotEmpty(t, body["access_token"], "response MUST include access_token")
	assert.Equal(t, "Bearer", body["token_type"])
	// RFC 7523 — no refresh token for jwt-bearer grant.
	_, hasRefresh := body["refresh_token"]
	assert.False(t, hasRefresh, "jwt-bearer MUST NOT return a refresh_token")
}

// TestJwtBearerGrant_NoTrustedIssuersConfigured — when the AS has no
// TrustedAssertionIssuers, the grant returns unsupported_grant_type.
func TestJwtBearerGrant_NoTrustedIssuersConfigured(t *testing.T) {
	a := &apiauth.APIAuth{
		JWTSecretKey: "test",
		JWTIssuer:    "oneauth-test",
		// TrustedAssertionIssuers intentionally empty.
	}
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", "irrelevant")

	status, body := postForm(t, a, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "unsupported_grant_type", body["error"])
}

// TestJwtBearerGrant_MissingAssertion — grant_type set but no assertion
// param yields invalid_request.
func TestJwtBearerGrant_MissingAssertion(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_request", body["error"])
}

// TestJwtBearerGrant_UntrustedIssuer — assertion signed by a key that
// matches no configured issuer is rejected with invalid_grant.
func TestJwtBearerGrant_UntrustedIssuer(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	assertion := env.mintAssertion(t, jwt.MapClaims{
		"iss": "https://malicious-idp.example.com",
	})
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", assertion)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Contains(t, body["error_description"], "untrusted")
}

// TestJwtBearerGrant_BadSignature — assertion claims a trusted iss but
// signature was made with a different key (i.e., attacker forged).
func TestJwtBearerGrant_BadSignature(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": env.idpIssuer,
		"sub": "alice",
		"aud": env.asAudience,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})
	signed, err := tok.SignedString(wrongKey)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", signed)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestJwtBearerGrant_ExpiredAssertion — exp in the past.
func TestJwtBearerGrant_ExpiredAssertion(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	assertion := env.mintAssertion(t, jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", assertion)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestJwtBearerGrant_AudienceMismatch — `aud` doesn't match what the AS
// expects.
func TestJwtBearerGrant_AudienceMismatch(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	assertion := env.mintAssertion(t, jwt.MapClaims{
		"aud": "https://different-resource.example.com",
	})
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", assertion)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Contains(t, body["error_description"], "audience")
}

// TestJwtBearerGrant_MissingSub — RFC 7523 §3 requires `sub`. An
// assertion that omits it is rejected.
func TestJwtBearerGrant_MissingSub(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	assertion := env.mintAssertion(t, jwt.MapClaims{
		"sub": nil, // delete the claim
	})
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", assertion)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestJwtBearerGrant_AlgorithmRestricted — when AcceptedAlgorithms is
// set to {"RS256"}, an HS256-signed assertion is rejected (alg-confusion
// mitigation: attacker can't downgrade to a symmetric algorithm whose
// "secret" is the issuer's public key).
func TestJwtBearerGrant_AlgorithmRestricted(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": env.idpIssuer,
		"sub": "alice",
		"aud": env.asAudience,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := tok.SignedString([]byte("not-the-real-secret"))
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", signed)

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestJwtBearerGrant_KeyFuncResolution — KeyFunc takes precedence over
// PublicKey. Useful for issuers whose JWKS rotates: the test pins a
// callback that returns a fresh key per request.
func TestJwtBearerGrant_KeyFuncResolution(t *testing.T) {
	env := newJwtBearerTestEnv(t)
	// Reconfigure: drop PublicKey, use KeyFunc instead.
	env.apiAuth.TrustedAssertionIssuers[0].PublicKey = nil
	env.apiAuth.TrustedAssertionIssuers[0].KeyFunc = func(*jwt.Token) (crypto.PublicKey, error) {
		return &env.idpKey.PublicKey, nil
	}

	assertion := env.mintAssertion(t, nil)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", assertion)

	status, _ := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusOK, status, "KeyFunc-based issuer MUST verify")
}
