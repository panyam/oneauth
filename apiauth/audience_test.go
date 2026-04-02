package apiauth_test

// Tests for audience (aud) claim validation in APIAuth.ValidateAccessToken
// and ValidateAccessTokenFull. These document the fix for #33: before the fix,
// audience was only checked in APIMiddleware.validateJWT but NOT in the
// ValidateAccessToken methods, allowing cross-service token acceptance.
//
// References:
//   - RFC 7519 §4.1.3: "The 'aud' claim identifies the recipients that the JWT
//     is intended for. [...] If the principal processing the claim does not identify
//     itself with a value in the 'aud' claim when this claim is present, then the
//     JWT MUST be rejected."
//   - OWASP JWT Cheat Sheet: "Always validate the audience claim to prevent tokens
//     intended for one service from being accepted by another."
//   - CWE-284: Improper Access Control — accepting tokens meant for other services.
//
// Scenario: Two microservices share the same signing key but have different
// JWTAudience values. A token minted for service-b should be rejected by
// service-a when validated via ValidateAccessToken.

import (
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

// TestAudience_WrongAud_Rejected_Full verifies the same for ValidateAccessTokenFull.
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
// bypass the check.
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
