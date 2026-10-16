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
// (CWE-613). Access tokens already issued run to their expiry.
//
// An email with no identity is not an error: there is nothing to revoke.
func NewRevokeSessionsOnReset(identities accounts.IdentityStore, refresh core.RefreshTokenStore) func(ctx context.Context, email string) error {
	return func(ctx context.Context, email string) error {
		resp, err := identities.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: email})
		if err != nil || resp == nil || resp.Identity == nil || resp.Identity.UserID == "" {
			return nil
		}
		if _, err := refresh.RevokeSubjectTokens(ctx, &core.RevokeSubjectTokensRequest{Subject: resp.Identity.UserID}); err != nil {
			return fmt.Errorf("revoke refresh tokens for %s: %w", resp.Identity.UserID, err)
		}
		return nil
	}
}
