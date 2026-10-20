package core

// ScopeOpenID is the scope that makes an authorization request an OpenID
// Connect request (OIDC Core §3.1.2.1). A grant carrying it gets an ID
// token, and its access token can read the userinfo endpoint.
const ScopeOpenID = "openid"

// OIDCScopeClaims maps each OIDC Core §5.4 scope to the standard claims
// it grants. The table is the spec's, not a policy: a deployment that
// wants other claims behind a scope filters them in its own
// UserClaims function.
var OIDCScopeClaims = map[string][]string{
	"profile": {
		"name", "family_name", "given_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "gender",
		"birthdate", "zoneinfo", "locale", "updated_at",
	},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// FilterClaimsByScope keeps the claims of claims that one of scopes grants
// under OIDCScopeClaims, and drops the rest. Claims no §5.4 scope names
// are dropped too, so a UserClaims function that returns a user's whole
// profile hands out only what the client was granted.
func FilterClaimsByScope(claims map[string]any, scopes []string) map[string]any {
	out := map[string]any{}
	for _, scope := range scopes {
		for _, name := range OIDCScopeClaims[scope] {
			if v, ok := claims[name]; ok {
				out[name] = v
			}
		}
	}
	return out
}
