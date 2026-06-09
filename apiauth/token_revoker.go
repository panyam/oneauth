package apiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/core"
)

// tokenRevoker implements TokenRevoker using a blacklist (for access tokens)
// and a RefreshTokenStore (for refresh tokens).
// Depends only on Blacklist + RefreshTokenStore — no HTTP, no transport.
type tokenRevoker struct {
	blacklist    core.TokenBlacklist
	refreshStore core.RefreshTokenStore
	hooks        TokenHooks
}

// TokenRevokerConfig configures a tokenRevoker.
type TokenRevokerConfig struct {
	Blacklist    core.TokenBlacklist
	RefreshStore core.RefreshTokenStore
	Hooks        TokenHooks
}

// NewTokenRevoker creates a TokenRevoker.
func NewTokenRevoker(cfg TokenRevokerConfig) TokenRevoker {
	return &tokenRevoker{
		blacklist:    cfg.Blacklist,
		refreshStore: cfg.RefreshStore,
		hooks:        cfg.Hooks,
	}
}

// Revoke invalidates a token. Tries refresh token first if no hint or
// hint is "refresh_token", then tries access token blacklisting.
//
// When the token resolves to a refresh token we capture its (subject, family,
// client_id) before the revoke completes and fire OnTokenRevoked so BCL
// dispatch can pick it up. Access-token blacklisting does not fire that hook
// because the access token already expires under its own ttl, and the refresh
// token (the real session anchor) is the right grain for BCL.
func (r *tokenRevoker) Revoke(ctx context.Context, req *RevokeRequest) (*RevokeResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("RevokeRequest is required")
	}
	var sub, sid, clientID string
	switch req.TokenTypeHint {
	case "refresh_token":
		sub, sid, clientID = r.revokeRefreshTokenInfo(ctx, req.Token)
	case "access_token":
		r.revokeAccessToken(req.Token)
	default:
		// No hint — try refresh first (cheaper lookup), then access
		var found bool
		sub, sid, clientID, found = r.revokeRefreshTokenInfoIfPresent(ctx, req.Token)
		if !found {
			r.revokeAccessToken(req.Token)
		}
	}

	r.hooks.fireOnRevoked(req.Token, req.TokenTypeHint)
	if sub != "" {
		r.hooks.fireOnTokenRevoked(sub, sid, clientID)
	}
	return &RevokeResponse{}, nil
}

// revokeRefreshTokenInfo revokes the refresh token and returns the
// (subject, sid, client_id) captured before revocation. Empty strings when
// the token doesn't resolve. Distinct from revokeRefreshTokenInfoIfPresent
// only in the boolean signal — the typed-hint path doesn't need to know
// whether to fall through to access-token revocation.
func (r *tokenRevoker) revokeRefreshTokenInfo(ctx context.Context, token string) (sub, sid, clientID string) {
	sub, sid, clientID, _ = r.revokeRefreshTokenInfoIfPresent(ctx, token)
	return sub, sid, clientID
}

// revokeRefreshTokenInfoIfPresent attempts to revoke a refresh token. Returns
// (subject, family-as-sid, client_id, found). The boolean lets the no-hint
// caller decide whether to fall through to access-token blacklisting.
func (r *tokenRevoker) revokeRefreshTokenInfoIfPresent(ctx context.Context, token string) (sub, sid, clientID string, found bool) {
	if r.refreshStore == nil {
		return "", "", "", false
	}
	getResp, err := r.refreshStore.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: token})
	if err != nil || getResp == nil || getResp.Token == nil {
		return "", "", "", false
	}
	sub = getResp.Token.Subject
	sid = getResp.Token.Family
	clientID = getResp.Token.ClientID
	if !getResp.Token.Revoked {
		r.refreshStore.RevokeRefreshToken(ctx, &core.RevokeRefreshTokenRequest{Token: token})
	}
	return sub, sid, clientID, true
}

// revokeAccessToken blacklists a JWT access token by its jti claim.
func (r *tokenRevoker) revokeAccessToken(token string) {
	if r.blacklist == nil {
		return
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return
	}

	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return
	}

	expiry := time.Now().Add(core.TokenExpiryAccessToken)
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		expiry = exp.Time
	}

	r.blacklist.Revoke(jti, expiry)
}
