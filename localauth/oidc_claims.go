package localauth

import (
	"context"
	"fmt"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
)

// ProfileClaims returns an OIDC claims function (apiauth.UserClaimsFunc)
// for users created by localauth. It maps the profile localauth keeps to
// the OIDC Core §5.1 standard claims and hands out only those the granted
// scopes allow (§5.4):
//
//	profile → preferred_username (from the profile's username)
//	email   → email, email_verified
//	phone   → phone_number, phone_number_verified
//
// The `_verified` claims come from the matching identity in identities,
// which is where localauth records a confirmed address. A nil identities
// store, or an address with no identity, reports false. A subject the user
// store does not know is an error, so the token endpoint answers
// server_error rather than issue an ID token for nobody.
func ProfileClaims(users accounts.UserStore, identities accounts.IdentityStore) func(ctx context.Context, subject string, scopes []string) (map[string]any, error) {
	return func(ctx context.Context, subject string, scopes []string) (map[string]any, error) {
		resp, err := users.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: subject})
		if err != nil {
			return nil, fmt.Errorf("load user %q: %w", subject, err)
		}
		profile := resp.User.Profile()

		verified := map[string]bool{}
		if identities != nil {
			ids, err := identities.GetUserIdentities(ctx, &accounts.GetUserIdentitiesRequest{UserID: subject})
			if err != nil {
				return nil, fmt.Errorf("load identities of %q: %w", subject, err)
			}
			for _, id := range ids.Identities {
				if id.Verified {
					verified[id.Type+":"+id.Value] = true
				}
			}
		}

		claims := map[string]any{}
		if v, ok := profile["username"].(string); ok && v != "" {
			claims["preferred_username"] = v
		}
		if v, ok := profile["email"].(string); ok && v != "" {
			claims["email"] = v
			claims["email_verified"] = verified["email:"+v]
		}
		if v, ok := profile["phone"].(string); ok && v != "" {
			claims["phone_number"] = v
			claims["phone_number_verified"] = verified["phone:"+v]
		}
		return core.FilterClaimsByScope(claims, scopes), nil
	}
}
