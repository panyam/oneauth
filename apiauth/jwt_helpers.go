package apiauth

import (
	"github.com/golang-jwt/jwt/v5"
)

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
