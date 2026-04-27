package apiauth

import (
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
func (r *tokenRevoker) Revoke(token, tokenTypeHint string) error {
	switch tokenTypeHint {
	case "refresh_token":
		r.revokeRefreshToken(token)
	case "access_token":
		r.revokeAccessToken(token)
	default:
		// No hint — try refresh first (cheaper lookup), then access
		if !r.revokeRefreshToken(token) {
			r.revokeAccessToken(token)
		}
	}

	r.hooks.fireOnRevoked(token, tokenTypeHint)
	return nil
}

// revokeRefreshToken attempts to revoke a refresh token. Returns true if
// the token was found in the refresh store.
func (r *tokenRevoker) revokeRefreshToken(token string) bool {
	if r.refreshStore == nil {
		return false
	}
	rt, err := r.refreshStore.GetRefreshToken(token)
	if err != nil || rt == nil {
		return false
	}
	if !rt.Revoked {
		r.refreshStore.RevokeRefreshToken(token)
	}
	return true
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
