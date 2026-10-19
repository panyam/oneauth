package apiauth

import (
	"context"
	"errors"
	"time"

	"github.com/panyam/oneauth/core"
)

// errRefreshRevoked reports that the refresh token an access token was
// issued with was revoked before the access token could be recorded on it.
var errRefreshRevoked = errors.New("refresh token was revoked")

// recordAccessToken records an access token on the refresh token issued
// with it (or redeemed for it), so revoking the family later blacklists it
// too (RFC 7009 §2.1). If the refresh token was revoked first, that
// revocation never saw this access token: it is blacklisted here and the
// grant gets errRefreshRevoked.
func recordAccessToken(ctx context.Context, store core.RefreshTokenStore, blacklist core.TokenBlacklist, refreshToken, tokenID string, expiresAt time.Time) error {
	if store == nil || refreshToken == "" || tokenID == "" {
		return nil
	}
	resp, err := store.RecordAccessToken(ctx, &core.RecordAccessTokenRequest{
		Token:     refreshToken,
		TokenID:   tokenID,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}
	if resp != nil && resp.Revoked {
		blacklistAccessTokens(blacklist, []core.IssuedAccessToken{{TokenID: tokenID, ExpiresAt: expiresAt}})
		return errRefreshRevoked
	}
	return nil
}

// revokeRefreshFamily revokes a refresh family and blacklists the access
// tokens its members recorded. Without a blacklist only the refresh
// tokens are revoked.
func revokeRefreshFamily(ctx context.Context, store core.RefreshTokenStore, blacklist core.TokenBlacklist, family string) error {
	if store == nil || family == "" {
		return nil
	}
	resp, err := store.RevokeTokenFamily(ctx, &core.RevokeTokenFamilyRequest{Family: family})
	if resp != nil {
		blacklistAccessTokens(blacklist, resp.AccessTokens)
	}
	return err
}

func blacklistAccessTokens(blacklist core.TokenBlacklist, tokens []core.IssuedAccessToken) {
	if blacklist == nil {
		return
	}
	for _, t := range tokens {
		if t.TokenID == "" {
			continue
		}
		expiresAt := t.ExpiresAt
		if expiresAt.IsZero() {
			expiresAt = time.Now().Add(core.TokenExpiryAccessToken)
		}
		_ = blacklist.Revoke(t.TokenID, expiresAt)
	}
}
