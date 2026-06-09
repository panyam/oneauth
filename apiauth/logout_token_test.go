package apiauth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken

const testBCLSecret = "test-signing-secret-do-not-use-in-prod"

func newTestLogoutIssuer(t *testing.T) LogoutTokenIssuer {
	t.Helper()
	return NewJWTLogoutTokenIssuer(JWTLogoutTokenIssuerConfig{
		SigningKey: []byte(testBCLSecret),
		SigningAlg: "HS256",
		Issuer:     "https://as.example.com",
		TokenTTL:   2 * time.Minute,
	})
}

func parseLogoutClaims(t *testing.T, tokenStr string) (jwt.MapClaims, *jwt.Token) {
	t.Helper()
	parsed, err := jwt.Parse(tokenStr, func(tok *jwt.Token) (any, error) {
		return []byte(testBCLSecret), nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims, parsed
}

func TestLogoutToken_ClaimsShape_SubjectAndSID(t *testing.T) {
	iss := newTestLogoutIssuer(t)
	resp, err := iss.CreateLogoutToken(context.Background(), &CreateLogoutTokenRequest{
		Audience: "client-abc",
		Subject:  "user-123",
		SID:      "fam-xyz",
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Token)

	claims, parsed := parseLogoutClaims(t, resp.Token)
	assert.Equal(t, "https://as.example.com", claims["iss"])
	assert.Equal(t, "client-abc", claims["aud"])
	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, "fam-xyz", claims["sid"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotZero(t, claims["iat"])
	assert.NotZero(t, claims["exp"])

	// events claim per §2.4 — single key with the BCL event-type URI, value
	// is an empty JSON object.
	ev, ok := claims["events"].(map[string]any)
	require.True(t, ok, "events claim must be a JSON object")
	body, ok := ev[BCLEventType]
	require.True(t, ok, "events must contain the BCL event-type URI")
	bodyMap, ok := body.(map[string]any)
	require.True(t, ok, "events[BCLEventType] must be an object")
	assert.Empty(t, bodyMap, "events[BCLEventType] must be an empty object")

	// nonce MUST NOT be present (§2.4 ¶6).
	_, hasNonce := claims["nonce"]
	assert.False(t, hasNonce, "nonce MUST NOT be present in logout_token")

	// typ=logout+jwt header so receivers can disambiguate.
	assert.Equal(t, "logout+jwt", parsed.Header["typ"])
}

func TestLogoutToken_SubjectOnly(t *testing.T) {
	iss := newTestLogoutIssuer(t)
	resp, err := iss.CreateLogoutToken(context.Background(), &CreateLogoutTokenRequest{
		Audience: "client-abc",
		Subject:  "user-123",
	})
	require.NoError(t, err)
	claims, _ := parseLogoutClaims(t, resp.Token)
	assert.Equal(t, "user-123", claims["sub"])
	_, hasSID := claims["sid"]
	assert.False(t, hasSID)
}

func TestLogoutToken_SIDOnly(t *testing.T) {
	iss := newTestLogoutIssuer(t)
	resp, err := iss.CreateLogoutToken(context.Background(), &CreateLogoutTokenRequest{
		Audience: "client-abc",
		SID:      "fam-xyz",
	})
	require.NoError(t, err)
	claims, _ := parseLogoutClaims(t, resp.Token)
	assert.Equal(t, "fam-xyz", claims["sid"])
	_, hasSub := claims["sub"]
	assert.False(t, hasSub)
}

func TestLogoutToken_MissingSubAndSID_Rejected(t *testing.T) {
	iss := newTestLogoutIssuer(t)
	_, err := iss.CreateLogoutToken(context.Background(), &CreateLogoutTokenRequest{
		Audience: "client-abc",
	})
	require.Error(t, err)
}

func TestLogoutToken_MissingAudience_Rejected(t *testing.T) {
	iss := newTestLogoutIssuer(t)
	_, err := iss.CreateLogoutToken(context.Background(), &CreateLogoutTokenRequest{
		Subject: "user-123",
	})
	require.Error(t, err)
}

func TestLogoutToken_NilRequest_Rejected(t *testing.T) {
	iss := newTestLogoutIssuer(t)
	_, err := iss.CreateLogoutToken(context.Background(), nil)
	require.Error(t, err)
}
