package apiauth

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// accessTokenParserOptions are the jwt.Parse options every access-token
// check uses. exp is required: a token without one would be valid forever
// (RFC 8725 §3.10).
func accessTokenParserOptions() []jwt.ParserOption {
	return []jwt.ParserOption{jwt.WithExpirationRequired()}
}

// checkAccessTokenKind refuses JWTs that verify with the same key but are
// something other than an access token: back-channel logout tokens and
// ID-JAGs are told apart by their JWS typ header, browser sessions by a
// type claim other than "access" (RFC 8725 §3.11). Tokens with no typ, typ
// "JWT" (Keycloak's) or the RFC 9068 "at+jwt" pass.
//
// Keycloak marks its tokens with a typ *claim* instead, and signs ID tokens
// with the same key, header and aud as access tokens, so that claim is the
// only difference: "Bearer" or "DPoP" is an access token, and anything else
// ("ID", "Refresh", "Logout") is refused.
func checkAccessTokenKind(token *jwt.Token, claims jwt.MapClaims) error {
	typ, _ := token.Header["typ"].(string)
	switch strings.ToLower(typ) {
	case "", "jwt", "at+jwt", "application/at+jwt":
	default:
		return fmt.Errorf("not an access token (typ %q)", typ)
	}
	if t, ok := claims["type"].(string); ok && t != "access" {
		return fmt.Errorf("invalid token type")
	}
	if t, ok := claims["typ"].(string); ok {
		switch strings.ToLower(t) {
		case "bearer", "dpop":
		default:
			return fmt.Errorf("not an access token (typ claim %q)", t)
		}
	}
	return nil
}

// checkTenantKey makes a tenant's key sign only for that tenant. A token
// verified with a key registered to a client must carry that client_id;
// without the check, a registered app could sign a token with no client_id
// and speak for any subject. ownKid is the kid of the verifier's own
// signing key: the AS's own tokens are exempt, since a grant with no
// client produces a token with no client_id. Keys with no owner (JWKS
// from a remote AS) are exempt too.
func checkTenantKey(rec *keys.KeyRecord, ownKid string, token *jwt.Token) error {
	if rec == nil || rec.ClientID == "" {
		return nil
	}
	if kid, _ := token.Header["kid"].(string); ownKid != "" && kid == ownKid {
		return nil
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	if claimClientID, _ := claims["client_id"].(string); claimClientID != rec.ClientID {
		return fmt.Errorf("key belongs to %q but the token's client_id is %q", rec.ClientID, claimClientID)
	}
	return nil
}

// kidOf is the kid a verifier's own key would sign with, or "" when there
// is no usable key.
func kidOf(key any, alg string) string {
	if b, ok := key.([]byte); ok && len(b) == 0 {
		return ""
	}
	if key == nil {
		return ""
	}
	if alg == "" {
		alg = "HS256"
	}
	kid, err := utils.ComputeKid(key, alg)
	if err != nil {
		return ""
	}
	return kid
}

// matchesAudience checks whether expectedAud appears in the JWT "aud"
// claim. Per RFC 7519 §4.1.3 the claim may be a single string or an
// array of strings; both shapes are accepted.
func matchesAudience(claims jwt.MapClaims, expectedAud string) bool {
	switch v := claims["aud"].(type) {
	case string:
		return v == expectedAud
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == expectedAud {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == expectedAud {
				return true
			}
		}
	}
	return false
}

// constantTimeEqual performs a constant-time string comparison so
// secret comparisons (client secrets, API key hashes) don't leak
// timing information. Length differences are still observable; this
// is acceptable for the high-entropy strings the comparison is used
// on.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
