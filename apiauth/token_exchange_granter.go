package apiauth

import (
	"context"
	"log"

	"github.com/panyam/oneauth/core"
)

// tokenExchanger implements TokenExchanger (RFC 8693 token exchange).
// Phase 1 supports two output types:
//
//   - requested_token_type=access_token (the default): a JWT subject_token
//     is traded for an access token, matching the legacy
//     APIAuth.handleTokenExchangeGrant.
//   - requested_token_type=id-jag: the subject_token is traded for an ID-JAG
//     assertion for the MCP Enterprise-Managed Authorization flow. Only
//     available when IDJAGIssuer is wired (opt-in); nil rejects id-jag
//     requests with invalid_request.
//
// The legacy APIAuth.handleTokenExchangeGrant (in token_exchange_grant.go)
// is preserved for the transition window so existing consumers keep
// working until they migrate to TokenEndpointHandler.
type tokenExchanger struct {
	trustedIssuers  []TrustedAssertionIssuer
	defaultAudience string
	defaultIssuer   string
	issuer          TokenIssuer
	idjagIssuer     IDJAGIssuer
}

// TokenExchangerConfig wires the dependencies the token-exchange grant
// needs. Build via NewTokenExchanger.
type TokenExchangerConfig struct {
	// TrustedIssuers lists upstream IdPs whose subject_tokens the grant
	// accepts. MUST be non-empty for the grant to do anything.
	TrustedIssuers []TrustedAssertionIssuer

	// DefaultAudience / DefaultIssuer supply the RFC 7523 §3 audience
	// fallback used when validating the subject_token and a
	// TrustedAssertionIssuer entry doesn't pin its own audience.
	DefaultAudience string
	DefaultIssuer   string

	// Issuer mints the access token for the access_token output path.
	// Required.
	Issuer TokenIssuer

	// IDJAGIssuer, when non-nil, opts the grant into
	// requested_token_type=id-jag issuance for the MCP EMA flow. Nil
	// (default) rejects id-jag requests — minting a cross-domain
	// authorization grant is off by default per #344.
	IDJAGIssuer IDJAGIssuer
}

// NewTokenExchanger constructs a TokenExchanger. cfg.TrustedIssuers MUST be
// non-empty for the grant to do anything.
func NewTokenExchanger(cfg TokenExchangerConfig) TokenExchanger {
	return &tokenExchanger{
		trustedIssuers:  cfg.TrustedIssuers,
		defaultAudience: cfg.DefaultAudience,
		defaultIssuer:   cfg.DefaultIssuer,
		issuer:          cfg.Issuer,
		idjagIssuer:     cfg.IDJAGIssuer,
	}
}

// TokenExchange trades subject_token for the requested token type per
// RFC 8693. The access_token path matches the legacy
// APIAuth.handleTokenExchangeGrant; the id-jag path mints an ID-JAG for the
// MCP EMA flow.
func (x *tokenExchanger) TokenExchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if len(x.trustedIssuers) == 0 {
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
	// Both a raw JWT (RFC 8693 §2.1.1) and an OIDC id_token are validated
	// the same way — as a signed JWT from a trusted issuer. The MCP EMA
	// client presents an id_token as the subject_token, so accept both.
	if req.SubjectTokenType != TokenTypeJWT && req.SubjectTokenType != TokenTypeIDToken {
		return nil, invalidRequest("only subject_token_type=" + TokenTypeJWT + " or " + TokenTypeIDToken + " is supported")
	}

	requestedType := req.RequestedTokenType
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}
	if requestedType != TokenTypeAccessToken && requestedType != TokenTypeIDJAG {
		return nil, invalidRequest("only requested_token_type=" + TokenTypeAccessToken + " or " + TokenTypeIDJAG + " is supported")
	}

	claims, _, err := ValidateAssertion(x.trustedIssuers, x.defaultAudience, x.defaultIssuer, req.SubjectToken)
	if err != nil {
		return nil, invalidGrant(err.Error())
	}
	subject, _ := claims["sub"].(string)

	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		return nil, &GrantError{Code: "invalid_authorization_details", Description: err.Error(), Status: 400}
	}

	if requestedType == TokenTypeIDJAG {
		return x.issueIDJAG(ctx, req, subject)
	}

	// access_token path — audience/resource remain advisory here until
	// audience-targeting lands on CreateAccessToken (issue tracked separately).
	if req.Audience != "" || req.Resource != "" {
		log.Printf("apiauth: token-exchange — audience=%q resource=%q params accepted but advisory for access_token output; issued token uses default audience.", req.Audience, req.Resource)
	}

	tok, err := x.issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{
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

// issueIDJAG handles requested_token_type=id-jag. Unlike the access_token
// path, audience is mandatory: it becomes the ID-JAG `aud` (the resource AS
// that will redeem it), so an ID-JAG with no target AS is not redeemable.
func (x *tokenExchanger) issueIDJAG(ctx context.Context, req *TokenExchangeRequest, subject string) (*TokenExchangeResponse, error) {
	if x.idjagIssuer == nil {
		return nil, invalidRequest("requested_token_type=" + TokenTypeIDJAG + " is not enabled (wire an IDJAGIssuer to opt in)")
	}
	if req.Audience == "" {
		return nil, invalidRequest("audience parameter required for requested_token_type=" + TokenTypeIDJAG)
	}

	// req.ClientID (the exchange `client_id` param) rides through as the
	// ID-JAG `client_id` claim so the redeeming AS can bind the eventual
	// access token to the client the IdP vouched for.
	res, err := x.idjagIssuer.CreateIDJAG(ctx, &CreateIDJAGRequest{
		Subject:              subject,
		Audience:             req.Audience,
		ClientID:             req.ClientID,
		Scopes:               req.Scopes,
		Resource:             req.Resource,
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		return nil, serverError("failed to create id-jag")
	}

	// Non-access-token output: RFC 8693 §2.2.1 sets token_type=N_A because
	// an ID-JAG is redeemed, not presented as a bearer credential.
	return &TokenExchangeResponse{Tokens: &core.TokenPair{
		AccessToken:          res.Token,
		TokenType:            TokenTypeNA,
		ExpiresIn:            res.ExpiresIn,
		Scope:                core.JoinScopes(req.Scopes),
		AuthorizationDetails: req.AuthorizationDetails,
		IssuedTokenType:      TokenTypeIDJAG,
	}}, nil
}

var _ TokenExchanger = (*tokenExchanger)(nil)
