package apiauth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/core"
)

// jwtBearerGranter implements JwtBearerGranter (RFC 7523
// §2.1). Validates the upstream-IdP assertion against the registered
// TrustedAssertionIssuers, then delegates token issuance to Issuer.
//
// When the assertion is an ID-JAG (JWS `typ` == oauth-id-jag+jwt) the
// granter applies the MCP EMA hardening on top of plain RFC 7523: it
// enforces single-use on the ID-JAG `jti` (an ID-JAG is single-use) and
// binds the issued access token to the ID-JAG `client_id`. Plain jwt-bearer
// assertions are unaffected.
//
// The legacy APIAuth.handleJwtBearerGrant (in jwt_bearer_grant.go) is
// preserved for the transition window so existing consumers keep
// working until they migrate to TokenEndpointHandler.
type jwtBearerGranter struct {
	trustedIssuers  []TrustedAssertionIssuer
	defaultAudience string
	defaultIssuer   string
	issuer          TokenIssuer
	replayStore     JTIStore
}

// JwtBearerGranterConfig wires the dependencies the jwt-bearer grant needs.
// Build via NewJwtBearerGranter.
type JwtBearerGranterConfig struct {
	// TrustedIssuers lists upstream IdPs whose assertions the grant
	// accepts. MUST be non-empty for the grant to do anything.
	TrustedIssuers []TrustedAssertionIssuer

	// DefaultAudience / DefaultIssuer supply the RFC 7523 §3 audience
	// fallback when a TrustedAssertionIssuer entry doesn't pin one. For
	// ID-JAG redemption these identify this AS so the ID-JAG `aud`
	// (= the resource AS the client redeems at) is checked against it.
	DefaultAudience string
	DefaultIssuer   string

	// Issuer mints the access token. Required.
	Issuer TokenIssuer

	// ReplayStore enforces single-use on redeemed ID-JAG assertions. Nil
	// defaults to an in-process in-memory store — swap in a distributed
	// implementation for multi-node deployments. Plain (non-ID-JAG)
	// jwt-bearer assertions are not replay-checked; the assertion is the
	// renewable credential per RFC 7523.
	ReplayStore JTIStore
}

// NewJwtBearerGranter constructs a JwtBearerGranter. cfg.TrustedIssuers MUST
// be non-empty for the grant to do anything.
func NewJwtBearerGranter(cfg JwtBearerGranterConfig) JwtBearerGranter {
	replay := cfg.ReplayStore
	if replay == nil {
		replay = NewInMemoryJTIStore()
	}
	return &jwtBearerGranter{
		trustedIssuers:  cfg.TrustedIssuers,
		defaultAudience: cfg.DefaultAudience,
		defaultIssuer:   cfg.DefaultIssuer,
		issuer:          cfg.Issuer,
		replayStore:     replay,
	}
}

// JwtBearerGrant validates the assertion and issues an access token
// bound to the assertion's subject. No refresh token is issued per
// RFC 7523 — the assertion itself is the renewable credential.
func (h *jwtBearerGranter) JwtBearerGrant(ctx context.Context, req *JwtBearerGrantRequest) (*JwtBearerGrantResponse, error) {
	if len(h.trustedIssuers) == 0 {
		return nil, unsupportedGrantType("jwt-bearer grant not configured")
	}
	if req == nil {
		return nil, invalidRequest("request is required")
	}
	if req.Assertion == "" {
		return nil, invalidRequest("assertion parameter required")
	}

	claims, _, err := ValidateAssertion(h.trustedIssuers, h.defaultAudience, h.defaultIssuer, req.Assertion)
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

	// ID-JAG hardening. `typ` is authenticated: ValidateAssertion verified
	// the signature over the same header we read here.
	var clientID string
	if assertionHeaderTyp(req.Assertion) == IDJAGTypeHeader {
		jti, _ := claims["jti"].(string)
		if jti == "" {
			return nil, invalidGrant("id-jag missing jti claim")
		}
		// Single-use: remember the jti until the ID-JAG expires. After
		// exp a replay fails on the exp check anyway, so we never need to
		// retain it longer.
		if h.replayStore.SeenWithin(jti, idjagReplayTTL(claims)) {
			return nil, invalidGrant("id-jag replay detected: jti already redeemed")
		}
		clientID, _ = claims["client_id"].(string)
		// TODO(ext-auth#13): propagate an act/actor claim so the access
		// token distinguishes the agent from the user it acts for.
	}

	tok, err := h.issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject:              subject,
		Scopes:               req.Scopes,
		AuthorizationDetails: req.AuthorizationDetails,
		ClientID:             clientID,
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

// idjagReplayTTL returns how long to remember an ID-JAG `jti` for replay
// detection: until the ID-JAG expires, falling back to the default lifetime
// when `exp` is absent or already past.
func idjagReplayTTL(claims jwt.MapClaims) time.Duration {
	if exp, ok := claims["exp"].(float64); ok {
		if d := time.Until(time.Unix(int64(exp), 0)); d > 0 {
			return d
		}
	}
	return idjagDefaultTTL
}

var _ JwtBearerGranter = (*jwtBearerGranter)(nil)
