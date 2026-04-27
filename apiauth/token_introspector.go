package apiauth

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// tokenIntrospector implements TokenIntrospector using local JWT validation.
// Depends only on TokenValidator (for token checking) — no HTTP, no transport.
type tokenIntrospector struct {
	validator TokenValidator
}

// NewTokenIntrospector creates a TokenIntrospector backed by a TokenValidator.
func NewTokenIntrospector(v TokenValidator) TokenIntrospector {
	return &tokenIntrospector{validator: v}
}

// Introspect checks a token and returns the result per RFC 7662.
// Returns {Active: false} for any invalid token — never reveals why.
func (ti *tokenIntrospector) Introspect(tokenString string) (*IntrospectionResult, error) {
	info, err := ti.validator.ValidateToken(tokenString)
	if err != nil {
		return &IntrospectionResult{Active: false}, nil
	}

	// Parse raw claims for the full introspection response
	// (ValidateToken strips standard claims from custom, but introspection
	// needs them all)
	rawClaims := parseRawJWTClaims(tokenString)

	result := &IntrospectionResult{
		Active:    true,
		Sub:       info.UserID,
		TokenType: "access_token",
	}

	// Add scope as space-separated string
	if len(info.Scopes) > 0 {
		result.Scope = strings.Join(info.Scopes, " ")
	}

	// Add standard claims from raw token
	if rawClaims != nil {
		if v, ok := rawClaims["iss"].(string); ok {
			result.Iss = v
		}
		if v, ok := rawClaims["exp"].(float64); ok {
			result.Exp = int64(v)
		}
		if v, ok := rawClaims["iat"].(float64); ok {
			result.Iat = int64(v)
		}
		if v, ok := rawClaims["jti"].(string); ok {
			result.Jti = v
		}
		if v, ok := rawClaims["aud"]; ok {
			result.Aud = v
		}
		if v, ok := rawClaims["client_id"].(string); ok {
			result.ClientID = v
		}
	}

	return result, nil
}

// parseRawJWTClaims extracts all claims from a JWT without validation.
func parseRawJWTClaims(tokenStr string) map[string]any {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	return claims
}
