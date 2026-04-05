package apiauth_test

// Tests for audience (aud) claim validation in APIAuth.ValidateAccessToken,
// ValidateAccessTokenFull, and APIMiddleware.validateJWT.
//
// History:
//   - #33: audience was only checked in APIMiddleware.validateJWT but NOT in
//     ValidateAccessToken methods — fixed to check at all validation sites.
//   - #52: all 3 sites used claims["aud"].(string) which silently fails when
//     aud is a JSON array. RFC 7519 §4.1.3 allows aud as either a single
//     string OR an array of strings. Keycloak, Auth0, Azure AD send arrays.
//     Fixed to handle both formats.
//
// References:
//   - RFC 7519 §4.1.3 (https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3):
//     "The 'aud' (audience) value is a case-sensitive string containing a
//     StringOrURI value. In the special case when the JWT has one audience,
//     the 'aud' value MAY be a single case-sensitive string containing a
//     StringOrURI value. In the general case, the 'aud' value is an array
//     of case-sensitive strings, each containing a StringOrURI value."
//   - OWASP JWT Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-audience):
//     "Always validate the audience claim to prevent tokens intended for one
//     service from being accepted by another."
//   - CWE-284 (https://cwe.mitre.org/data/definitions/284.html):
//     Improper Access Control — accepting tokens meant for other services.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintToken creates a signed JWT with the given claims for testing.
func mintToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

// baseClaims returns the minimum valid access token claims.
func baseClaims(aud string) jwt.MapClaims {
	c := jwt.MapClaims{
		"sub":    "user1",
		"type":   "access",
		"scopes": []string{"read"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}
	if aud != "" {
		c["aud"] = aud
	}
	return c
}

// =============================================================================
// These tests FAIL before the fix — ValidateAccessToken does not check aud.
// =============================================================================

// TestAudience_WrongAud_Rejected verifies that a token with aud="service-b"
// is rejected when APIAuth.JWTAudience is "service-a". This is the core
// cross-service attack scenario.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://cwe.mitre.org/data/definitions/284.html
//
// BEFORE FIX: passes (token accepted despite wrong audience)
// AFTER FIX: fails with "invalid audience"
func TestAudience_WrongAud_Rejected(t *testing.T) {
	secret := "shared-secret-between-services"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	// Token was minted for service-b
	token := mintToken(t, secret, baseClaims("service-b"))

	_, _, err := auth.ValidateAccessToken(token)
	if assert.Error(t, err, "ValidateAccessToken should reject token with wrong audience") {
		assert.Contains(t, err.Error(), "audience")
	}
}

// TestAudience_WrongAud_Rejected_Full verifies the same cross-service attack
// for ValidateAccessTokenFull.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
func TestAudience_WrongAud_Rejected_Full(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, baseClaims("service-b"))

	_, _, _, err := auth.ValidateAccessTokenFull(token)
	if assert.Error(t, err, "ValidateAccessTokenFull should reject token with wrong audience") {
		assert.Contains(t, err.Error(), "audience")
	}
}

// TestAudience_MissingAud_Rejected verifies that a token WITHOUT an aud claim
// is rejected when JWTAudience is configured. A missing audience should not
// bypass the check — omitting the claim entirely is a common attack variant.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
func TestAudience_MissingAud_Rejected(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	// Token has no aud claim at all
	token := mintToken(t, secret, baseClaims(""))

	_, _, err := auth.ValidateAccessToken(token)
	if assert.Error(t, err, "ValidateAccessToken should reject token missing audience when JWTAudience is configured") {
		assert.Contains(t, err.Error(), "audience")
	}
}

// =============================================================================
// These tests PASS both before and after the fix — documenting correct behavior.
// =============================================================================

// TestAudience_CorrectAud_Accepted verifies that a token with the correct
// audience is accepted.
func TestAudience_CorrectAud_Accepted(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, baseClaims("service-a"))

	userID, scopes, err := auth.ValidateAccessToken(token)
	assert.NoError(t, err)
	assert.Equal(t, "user1", userID)
	assert.Contains(t, scopes, "read")
}

// TestAudience_NoAudienceConfigured_AcceptsAll verifies backward compatibility:
// when JWTAudience is not set (empty string), any token is accepted regardless
// of its aud claim. This preserves existing behavior for single-service deployments.
func TestAudience_NoAudienceConfigured_AcceptsAll(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		// JWTAudience not set — no audience validation
	}

	// Token with some audience — should be accepted
	token := mintToken(t, secret, baseClaims("any-service"))
	userID, _, err := auth.ValidateAccessToken(token)
	assert.NoError(t, err)
	assert.Equal(t, "user1", userID)

	// Token with no audience — should also be accepted
	token2 := mintToken(t, secret, baseClaims(""))
	userID2, _, err := auth.ValidateAccessToken(token2)
	assert.NoError(t, err)
	assert.Equal(t, "user1", userID2)
}

// TestAudience_CorrectAud_Full verifies ValidateAccessTokenFull accepts
// correct audience and returns custom claims.
func TestAudience_CorrectAud_Full(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	claims := baseClaims("service-a")
	claims["tenant"] = "acme"
	token := mintToken(t, secret, claims)

	userID, _, customClaims, err := auth.ValidateAccessTokenFull(token)
	assert.NoError(t, err)
	assert.Equal(t, "user1", userID)
	assert.Equal(t, "acme", customClaims["tenant"])
}

// =============================================================================
// Array audience tests (#52) — RFC 7519 §4.1.3 allows aud as string OR array.
// These tests FAIL before the fix because claims["aud"].(string) returns ""
// when aud is a JSON array, causing validation to silently reject valid tokens
// or accept invalid ones.
// =============================================================================

// arrayAudClaims returns valid access token claims with aud set as an array
// of strings, as sent by Keycloak, Auth0, Azure AD, and other OIDC providers.
func arrayAudClaims(audiences []string) jwt.MapClaims {
	return jwt.MapClaims{
		"sub":    "user1",
		"type":   "access",
		"scopes": []string{"read"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"aud":    audiences,
	}
}

// TestAudience_ArrayAud_Matching_Accepted verifies that a token with
// aud: ["service-a", "service-b"] is accepted when JWTAudience is "service-a".
// This is the standard case for tokens from Keycloak and other IdPs that
// include multiple audiences (e.g., the client_id and an API resource).
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestAudience_ArrayAud_Matching_Accepted(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, arrayAudClaims([]string{"service-a", "service-b"}))

	userID, scopes, err := auth.ValidateAccessToken(token)
	assert.NoError(t, err, "ValidateAccessToken should accept token with matching audience in array")
	assert.Equal(t, "user1", userID)
	assert.Contains(t, scopes, "read")
}

// TestAudience_ArrayAud_NotMatching_Rejected verifies that a token with
// aud: ["service-b", "service-c"] is rejected when JWTAudience is "service-a".
// The expected audience is not in the array, so validation must fail.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestAudience_ArrayAud_NotMatching_Rejected(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, arrayAudClaims([]string{"service-b", "service-c"}))

	_, _, err := auth.ValidateAccessToken(token)
	if assert.Error(t, err, "ValidateAccessToken should reject token when expected audience not in array") {
		assert.Contains(t, err.Error(), "audience")
	}
}

// TestAudience_ArrayAud_Full_Accepted verifies that ValidateAccessTokenFull
// correctly handles aud as an array when the expected audience is present.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestAudience_ArrayAud_Full_Accepted(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	claims := arrayAudClaims([]string{"service-a", "other"})
	claims["tenant"] = "acme"
	token := mintToken(t, secret, claims)

	userID, _, customClaims, err := auth.ValidateAccessTokenFull(token)
	assert.NoError(t, err, "ValidateAccessTokenFull should accept token with matching audience in array")
	assert.Equal(t, "user1", userID)
	assert.Equal(t, "acme", customClaims["tenant"])
}

// TestAudience_ArrayAud_Full_Rejected verifies that ValidateAccessTokenFull
// rejects tokens where the expected audience is not in the array.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestAudience_ArrayAud_Full_Rejected(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, arrayAudClaims([]string{"service-b"}))

	_, _, _, err := auth.ValidateAccessTokenFull(token)
	if assert.Error(t, err, "ValidateAccessTokenFull should reject token when expected audience not in array") {
		assert.Contains(t, err.Error(), "audience")
	}
}

// TestAudience_ArrayAud_Middleware_Accepted verifies that APIMiddleware
// correctly validates tokens with aud as an array via HTTP request.
// This tests the full middleware path including context injection.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestAudience_ArrayAud_Middleware_Accepted(t *testing.T) {
	secret := "shared-secret"
	middleware := &apiauth.APIMiddleware{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, arrayAudClaims([]string{"service-a", "service-b"}))

	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := apiauth.GetUserIDFromAPIContext(r.Context())
		assert.Equal(t, "user1", userID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "Middleware should accept token with matching audience in array")
}

// TestAudience_ArrayAud_Middleware_Rejected verifies that APIMiddleware
// rejects tokens via HTTP when the expected audience is not in the array.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestAudience_ArrayAud_Middleware_Rejected(t *testing.T) {
	secret := "shared-secret"
	middleware := &apiauth.APIMiddleware{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, arrayAudClaims([]string{"service-b", "service-c"}))

	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for rejected token")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Middleware should reject token when expected audience not in array")
}

// TestAudience_EmptyArray_Rejected verifies that a token with an empty
// aud array is rejected when JWTAudience is configured. An empty array
// means "no intended audience" which should not match any expected audience.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestAudience_EmptyArray_Rejected(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, arrayAudClaims([]string{}))

	_, _, err := auth.ValidateAccessToken(token)
	if assert.Error(t, err, "ValidateAccessToken should reject token with empty audience array") {
		assert.Contains(t, err.Error(), "audience")
	}
}

// TestAudience_SingleElementArray_Accepted verifies that a token with
// aud: ["service-a"] (single-element array) is accepted. Some IdPs always
// send an array even when there's only one audience.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// See: https://github.com/panyam/oneauth/issues/52
func TestAudience_SingleElementArray_Accepted(t *testing.T) {
	secret := "shared-secret"
	auth := &apiauth.APIAuth{
		JWTSecretKey: secret,
		JWTAudience:  "service-a",
	}

	token := mintToken(t, secret, arrayAudClaims([]string{"service-a"}))

	userID, _, err := auth.ValidateAccessToken(token)
	assert.NoError(t, err, "ValidateAccessToken should accept single-element array with matching audience")
	assert.Equal(t, "user1", userID)
}
