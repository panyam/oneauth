package apiauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/core"
)

// tokenIntrospector implements TokenIntrospector using local JWT validation,
// and a refresh-token store when one is given.
// Depends only on TokenValidator + RefreshTokenStore — no HTTP, no transport.
type tokenIntrospector struct {
	validator    TokenValidator
	refreshStore core.RefreshTokenStore
}

// NewTokenIntrospector creates a TokenIntrospector backed by a TokenValidator.
// It reports only access tokens; refresh tokens come back inactive.
func NewTokenIntrospector(v TokenValidator) TokenIntrospector {
	return &tokenIntrospector{validator: v}
}

// NewTokenIntrospectorWithRefreshStore is NewTokenIntrospector plus refresh
// tokens (RFC 7662 §2.1): a refresh token in rs that is neither revoked nor
// expired introspects as active, with its sub, client_id, scope and exp. A
// nil rs behaves like NewTokenIntrospector.
func NewTokenIntrospectorWithRefreshStore(v TokenValidator, rs core.RefreshTokenStore) TokenIntrospector {
	return &tokenIntrospector{validator: v, refreshStore: rs}
}

// Introspect checks a token and returns the result per RFC 7662.
// Returns {Active: false} for any invalid token — never reveals why.
// TokenTypeHint only decides which kind is tried first.
func (ti *tokenIntrospector) Introspect(ctx context.Context, req *IntrospectRequest) (*IntrospectResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("IntrospectRequest is required")
	}
	if req.TokenTypeHint == "refresh_token" {
		if res := ti.introspectRefresh(ctx, req.Token); res != nil {
			return &IntrospectResponse{Result: res}, nil
		}
	}
	tokenString := req.Token
	resp, err := ti.validator.ValidateToken(ctx, &ValidateTokenRequest{Token: tokenString})
	if err != nil {
		if res := ti.introspectRefresh(ctx, req.Token); res != nil {
			return &IntrospectResponse{Result: res}, nil
		}
		return &IntrospectResponse{Result: &IntrospectionResult{Active: false}}, nil
	}
	info := resp.Info

	// Parse raw claims for the full introspection response
	// (ValidateToken strips standard claims from custom, but introspection
	// needs them all)
	rawClaims := parseRawJWTClaims(tokenString)

	result := &IntrospectionResult{
		Active: true,
		Sub:    info.Subject,
		// RFC 7662 §2.2: the RFC 6749 §7.1 type, as the token response said.
		TokenType: tokenTypeFor(info.Confirmation),
		// Sender-constraint travels with the introspection response so a
		// resource server that does not validate the JWT itself can still
		// enforce the binding (RFC 9449 §6).
		Cnf: info.Confirmation,
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

	return &IntrospectResponse{Result: result}, nil
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

// introspectRefresh reports a refresh token from the store, or nil when
// there is no store or the token isn't in it. A revoked or expired one is
// reported inactive. It carries no token_type, which names access-token
// types only.
func (ti *tokenIntrospector) introspectRefresh(ctx context.Context, token string) *IntrospectionResult {
	if ti.refreshStore == nil {
		return nil
	}
	got, err := ti.refreshStore.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: token})
	if err != nil || got == nil || got.Token == nil {
		return nil
	}
	rt := got.Token
	if !rt.IsValid() {
		return &IntrospectionResult{Active: false}
	}
	return &IntrospectionResult{
		Active:   true,
		Sub:      rt.Subject,
		ClientID: rt.ClientID,
		Scope:    strings.Join(rt.Scopes, " "),
		Exp:      rt.ExpiresAt.Unix(),
		Cnf:      rt.Confirmation,
	}
}
