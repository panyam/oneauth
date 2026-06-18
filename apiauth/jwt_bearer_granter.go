package apiauth

import (
	"context"

	"github.com/panyam/oneauth/core"
)

// jwtBearerGranter implements JwtBearerGranter (RFC 7523
// §2.1). Validates the upstream-IdP assertion against the registered
// TrustedAssertionIssuers, then delegates token issuance to Issuer.
//
// The legacy APIAuth.handleJwtBearerGrant (in jwt_bearer_grant.go) is
// preserved for the transition window so existing consumers keep
// working until they migrate to TokenEndpointHandler.
type jwtBearerGranter struct {
	TrustedIssuers  []TrustedAssertionIssuer
	DefaultAudience string
	DefaultIssuer   string
	Issuer          TokenIssuer
}

// NewJwtBearerGranter constructs a JwtBearerGranter.
// trustedIssuers MUST be non-empty for the grant to do anything;
// defaultAudience / defaultIssuer supply the RFC 7523 §3 audience
// fallback when a TrustedAssertionIssuer entry doesn't pin one.
func NewJwtBearerGranter(trustedIssuers []TrustedAssertionIssuer, defaultAudience, defaultIssuer string, issuer TokenIssuer) JwtBearerGranter {
	return &jwtBearerGranter{
		TrustedIssuers:  trustedIssuers,
		DefaultAudience: defaultAudience,
		DefaultIssuer:   defaultIssuer,
		Issuer:          issuer,
	}
}

// JwtBearerGrant validates the assertion and issues an access token
// bound to the assertion's subject. No refresh token is issued per
// RFC 7523 — the assertion itself is the renewable credential.
func (h *jwtBearerGranter) JwtBearerGrant(ctx context.Context, req *JwtBearerGrantRequest) (*JwtBearerGrantResponse, error) {
	if len(h.TrustedIssuers) == 0 {
		return nil, unsupportedGrantType("jwt-bearer grant not configured")
	}
	if req == nil {
		return nil, invalidRequest("request is required")
	}
	if req.Assertion == "" {
		return nil, invalidRequest("assertion parameter required")
	}

	claims, _, err := ValidateAssertion(h.TrustedIssuers, h.DefaultAudience, h.DefaultIssuer, req.Assertion)
	if err != nil {
		return nil, invalidGrant(err.Error())
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		return nil, invalidGrant("assertion missing sub claim")
	}

	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		return nil, &GrantError{Code: "invalid_authorization_details", Description: err.Error(), Status: 400}
	}

	tok, err := h.Issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject:              subject,
		Scopes:               req.Scopes,
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		return nil, serverError("failed to create token")
	}

	return &JwtBearerGrantResponse{Tokens: &core.TokenPair{
		AccessToken:          tok.Token,
		TokenType:            "Bearer",
		ExpiresIn:            tok.ExpiresIn,
		Scope:                joinScopes(req.Scopes),
		AuthorizationDetails: req.AuthorizationDetails,
	}}, nil
}

var _ JwtBearerGranter = (*jwtBearerGranter)(nil)
