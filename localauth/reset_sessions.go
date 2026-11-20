package localauth

import (
	"context"
	"fmt"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
)

// NewRevokeSessionsOnReset returns an AfterPasswordReset hook that finds
// the account by its email identity and revokes all of its refresh
// tokens, so a session opened with the old password ends with it
// (CWE-613). Access tokens already issued run to their expiry; use
// NewRevokeSessionsOnResetWithBlacklist to cut them off too.
//
// An email with no identity is not an error: there is nothing to revoke.
func NewRevokeSessionsOnReset(identities accounts.IdentityStore, refresh core.RefreshTokenStore) func(ctx context.Context, email string) error {
	return NewRevokeSessionsOnResetWithBlacklist(identities, refresh, nil)
}

// NewRevokeSessionsOnResetWithBlacklist is NewRevokeSessionsOnReset that
// also puts the access tokens recorded on the revoked refresh tokens on
// blacklist, so they stop working at once (RFC 7009 §2.1). Pass the
// blacklist the resource servers' middleware checks. A nil blacklist
// behaves like NewRevokeSessionsOnReset.
func NewRevokeSessionsOnResetWithBlacklist(identities accounts.IdentityStore, refresh core.RefreshTokenStore, blacklist core.TokenBlacklist) func(ctx context.Context, email string) error {
	return func(ctx context.Context, email string) error {
		resp, err := identities.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: email})
		if err != nil || resp == nil || resp.Identity == nil || resp.Identity.UserID == "" {
			return nil
		}
		revoked, err := refresh.RevokeSubjectTokens(ctx, &core.RevokeSubjectTokensRequest{Subject: resp.Identity.UserID})
		if revoked != nil {
			core.BlacklistIssuedAccessTokens(blacklist, revoked.AccessTokens)
		}
		if err != nil {
			return fmt.Errorf("revoke refresh tokens for %s: %w", resp.Identity.UserID, err)
		}
		return nil
	}
}
