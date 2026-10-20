package apiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/panyam/oneauth/core"
)

// tokenRevoker implements TokenRevoker using a blacklist (for access tokens)
// and a RefreshTokenStore (for refresh tokens).
// Depends only on Blacklist + RefreshTokenStore + Validator — no HTTP, no transport.
type tokenRevoker struct {
	blacklist    core.TokenBlacklist
	refreshStore core.RefreshTokenStore
	validator    TokenValidator
	hooks        TokenHooks
}

// TokenRevokerConfig configures a tokenRevoker.
type TokenRevokerConfig struct {
	Blacklist    core.TokenBlacklist
	RefreshStore core.RefreshTokenStore

	// Validator verifies an access token before its jti is blacklisted,
	// so a forged token naming someone else's jti can't revoke theirs.
	// Without one, access tokens are never blacklisted.
	Validator TokenValidator

	Hooks TokenHooks
}

// NewTokenRevoker creates a TokenRevoker.
func NewTokenRevoker(cfg TokenRevokerConfig) TokenRevoker {
	return &tokenRevoker{
		blacklist:    cfg.Blacklist,
		refreshStore: cfg.RefreshStore,
		validator:    cfg.Validator,
		hooks:        cfg.Hooks,
	}
}

// Revoke invalidates a token. It looks the token up as a refresh token
// first and otherwise treats it as an access token, whatever the hint.
//
// A token that doesn't resolve, or doesn't verify, is not an error: RFC
// 7009 §2.2 answers it like a success. A token issued to a client other
// than req.ClientID returns ErrRevokeNotOwner and is left alone.
//
// Revoking a refresh token revokes its whole family and blacklists the
// access tokens the family recorded (RFC 7009 §2.1), when a Blacklist is
// configured.
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
	rt := r.lookupRefreshToken(ctx, req.Token)
	// The hint only orders the search, and RFC 7009 §2.1 has the server
	// try every type it supports; the refresh lookup is the cheap one.
	if rt == nil {
		if err := r.revokeAccessToken(ctx, req.Token, req.ClientID); err != nil {
			return nil, err
		}
		r.hooks.fireOnRevoked(req.Token, req.TokenTypeHint)
		return &RevokeResponse{}, nil
	}
	if rt != nil {
		if !ownedBy(rt.ClientID, req.ClientID) {
			return nil, ErrRevokeNotOwner
		}
		// RFC 7009 §2.1: the access tokens issued from the same grant go
		// too. The family is the grant, so the whole of it is revoked,
		// whichever member was presented.
		if rt.Family != "" {
			revokeRefreshFamily(ctx, r.refreshStore, r.blacklist, rt.Family)
		} else if !rt.Revoked {
			r.refreshStore.RevokeRefreshToken(ctx, &core.RevokeRefreshTokenRequest{Token: req.Token})
		}
	}

	r.hooks.fireOnRevoked(req.Token, req.TokenTypeHint)
	if rt != nil && rt.Subject != "" {
		r.hooks.fireOnTokenRevoked(rt.Subject, rt.Family, rt.ClientID)
	}
	return &RevokeResponse{}, nil
}

// ownedBy reports whether a token issued to tokenClient may be revoked by
// caller. An empty caller is the AS acting for itself; a token with no
// client has nobody else to belong to.
func ownedBy(tokenClient, caller string) bool {
	return caller == "" || tokenClient == "" || tokenClient == caller
}

// lookupRefreshToken returns the stored refresh token, or nil when there is
// no refresh store or the token isn't in it.
func (r *tokenRevoker) lookupRefreshToken(ctx context.Context, token string) *core.RefreshToken {
	if r.refreshStore == nil {
		return nil
	}
	getResp, err := r.refreshStore.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: token})
	if err != nil || getResp == nil {
		return nil
	}
	return getResp.Token
}

// revokeAccessToken blacklists a JWT access token by its jti claim, after
// the validator has verified it. Every claim it acts on comes from the
// verified token. Tokens that don't verify (forged, expired, already
// revoked) are left alone.
func (r *tokenRevoker) revokeAccessToken(ctx context.Context, token, caller string) error {
	if r.blacklist == nil || r.validator == nil {
		return nil
	}
	resp, err := r.validator.ValidateToken(ctx, &ValidateTokenRequest{Token: token})
	if err != nil || resp == nil || resp.Info == nil {
		return nil
	}
	info := resp.Info
	if !ownedBy(info.ClientID, caller) {
		return ErrRevokeNotOwner
	}
	if info.TokenID == "" {
		return nil
	}

	expiry := info.ExpiresAt
	if expiry.IsZero() {
		expiry = time.Now().Add(core.TokenExpiryAccessToken)
	}
	r.blacklist.Revoke(info.TokenID, expiry)
	return nil
}
