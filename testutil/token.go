package testutil

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
)

// MintToken creates a valid RS256 JWT with standard claims for the given
// user and scopes. This is a fast path that bypasses the HTTP token endpoint
// — no network round-trip is involved.
//
// The token includes: sub, iss, aud (if configured), type ("access"),
// scopes, iat, exp (15 min), jti, and a kid header matching the server's
// JWKS-published key.
//
// See: https://www.rfc-editor.org/rfc/rfc7519 (JWT)
func (s *TestAuthServer) MintToken(userID string, scopes []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":    userID,
		"iss":    s.cfg.issuer,
		"type":   "access",
		"scopes": scopes,
		"iat":    now.Unix(),
		"exp":    now.Add(15 * time.Minute).Unix(),
	}
	if s.cfg.audience != "" {
		claims["aud"] = s.cfg.audience
	}
	jti, err := core.GenerateSecureToken()
	if err != nil {
		return "", err
	}
	claims["jti"] = jti

	return s.signToken(claims)
}

// MintTokenWithClaims creates an RS256 JWT with arbitrary claims. Standard
// defaults (iss, iat, exp) are set but can be overridden by the provided
// claims map. This is useful for testing edge cases: wrong issuer, expired
// tokens, missing claims, etc.
//
// The kid header is always set to match the server's JWKS key.
//
// See: https://www.rfc-editor.org/rfc/rfc7519 (JWT)
func (s *TestAuthServer) MintTokenWithClaims(claims jwt.MapClaims) (string, error) {
	now := time.Now()

	// Set defaults (caller can override)
	defaults := jwt.MapClaims{
		"iss": s.cfg.issuer,
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}
	for k, v := range defaults {
		if _, exists := claims[k]; !exists {
			claims[k] = v
		}
	}

	return s.signToken(claims)
}

// signToken creates and signs a JWT with RS256, setting the kid header.
func (s *TestAuthServer) signToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	kid, err := utils.ComputeKid(s.privateKey, "RS256")
	if err != nil {
		return "", err
	}
	token.Header["kid"] = kid
	return token.SignedString(s.privateKey)
}
