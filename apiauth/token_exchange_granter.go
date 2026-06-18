package apiauth

import (
	"context"
	"log"

	"github.com/panyam/oneauth/core"
)

// tokenExchanger implements TokenExchanger (RFC 8693 token exchange).
// Phase 1 supports JWT subject_tokens → access_token output; other
// type combinations return invalid_request and are tracked as
// follow-ups.
//
// The legacy APIAuth.handleTokenExchangeGrant (in token_exchange_grant.go)
// is preserved for the transition window so existing consumers keep
// working until they migrate to TokenEndpointHandler.
type tokenExchanger struct {
	TrustedIssuers  []TrustedAssertionIssuer
	DefaultAudience string
	DefaultIssuer   string
	Issuer          TokenIssuer
}

// NewTokenExchanger constructs a TokenExchanger. trustedIssuers MUST
// be non-empty for the grant to do anything.
func NewTokenExchanger(trustedIssuers []TrustedAssertionIssuer, defaultAudience, defaultIssuer string, issuer TokenIssuer) TokenExchanger {
	return &tokenExchanger{
		TrustedIssuers:  trustedIssuers,
		DefaultAudience: defaultAudience,
		DefaultIssuer:   defaultIssuer,
		Issuer:          issuer,
	}
}

// TokenExchange trades subject_token for an access token per
// RFC 8693. Behavior matches the legacy
// APIAuth.handleTokenExchangeGrant.
func (x *tokenExchanger) TokenExchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if len(x.TrustedIssuers) == 0 {
		return nil, unsupportedGrantType("token-exchange grant not configured")
	}
	if req == nil {
		return nil, invalidRequest("request is required")
	}
	if req.SubjectToken == "" {
		return nil, invalidRequest("subject_token parameter required")
	}
	if req.SubjectTokenType == "" {
		return nil, invalidRequest("subject_token_type parameter required")
	}
	if req.SubjectTokenType != TokenTypeJWT {
		return nil, invalidRequest("only subject_token_type=" + TokenTypeJWT + " is supported")
	}

	requestedType := req.RequestedTokenType
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}
	if requestedType != TokenTypeAccessToken {
		return nil, invalidRequest("only requested_token_type=" + TokenTypeAccessToken + " is supported")
	}

	claims, _, err := ValidateAssertion(x.TrustedIssuers, x.DefaultAudience, x.DefaultIssuer, req.SubjectToken)
	if err != nil {
		return nil, invalidGrant(err.Error())
	}
	subject, _ := claims["sub"].(string)

	if req.Audience != "" || req.Resource != "" {
		log.Printf("apiauth: token-exchange — audience=%q resource=%q params accepted but advisory; issued token uses default audience. Bind these into CreateAccessToken when audience-targeting lands.", req.Audience, req.Resource)
	}

	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		return nil, &GrantError{Code: "invalid_authorization_details", Description: err.Error(), Status: 400}
	}

	tok, err := x.Issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject:              subject,
		Scopes:               req.Scopes,
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		return nil, serverError("failed to create token")
	}

	return &TokenExchangeResponse{Tokens: &core.TokenPair{
		AccessToken:          tok.Token,
		TokenType:            "Bearer",
		ExpiresIn:            tok.ExpiresIn,
		Scope:                core.JoinScopes(req.Scopes),
		AuthorizationDetails: req.AuthorizationDetails,
		IssuedTokenType:      requestedType,
	}}, nil
}

var _ TokenExchanger = (*tokenExchanger)(nil)
