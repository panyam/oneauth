package oneauth

import (
	"strings"
)

// Built-in scope constants
const (
	ScopeRead    = "read"    // Read access to user data
	ScopeWrite   = "write"   // Write access to user data
	ScopeProfile = "profile" // Access to user profile information
	ScopeOffline = "offline" // Enable refresh tokens (long-lived sessions)
	ScopeAdmin   = "admin"   // Administrative access
)

// AllBuiltinScopes returns all built-in scope values
func AllBuiltinScopes() []string {
	return []string{ScopeRead, ScopeWrite, ScopeProfile, ScopeOffline, ScopeAdmin}
}

// GetUserScopesFunc is a callback that returns allowed scopes for a user.
// Applications implement this to determine what scopes a user is allowed to have.
// This can be based on user roles, profile data, groups, etc.
type GetUserScopesFunc func(userID string) ([]string, error)

// DefaultGetUserScopes returns a default implementation that grants basic scopes to all users
func DefaultGetUserScopes() GetUserScopesFunc {
	return func(userID string) ([]string, error) {
		return []string{ScopeRead, ScopeWrite, ScopeProfile, ScopeOffline}, nil
	}
}

// ParseScopes parses a space-separated scope string into a slice
func ParseScopes(scopeString string) []string {
	if scopeString == "" {
		return nil
	}
	scopes := strings.Fields(scopeString)
	// Remove duplicates
	seen := make(map[string]bool)
	result := make([]string, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// JoinScopes joins a slice of scopes into a space-separated string
func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// IntersectScopes returns the intersection of requested and allowed scopes
// The result contains only scopes that appear in both slices
func IntersectScopes(requested, allowed []string) []string {
	allowedSet := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = true
	}

	result := make([]string, 0, len(requested))
	seen := make(map[string]bool)
	for _, s := range requested {
		if allowedSet[s] && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ContainsScope checks if a scope is present in the list
func ContainsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ContainsAllScopes checks if all required scopes are present in the granted scopes
func ContainsAllScopes(granted, required []string) bool {
	grantedSet := make(map[string]bool, len(granted))
	for _, s := range granted {
		grantedSet[s] = true
	}
	for _, s := range required {
		if !grantedSet[s] {
			return false
		}
	}
	return true
}

// ValidateRequestedScopes validates that all requested scopes are from the allowed set
// Returns the valid scopes and any invalid scopes found
func ValidateRequestedScopes(requested, allowed []string) (valid, invalid []string) {
	allowedSet := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = true
	}

	valid = make([]string, 0, len(requested))
	invalid = make([]string, 0)
	seen := make(map[string]bool)

	for _, s := range requested {
		if seen[s] {
			continue // Skip duplicates
		}
		seen[s] = true
		if allowedSet[s] {
			valid = append(valid, s)
		} else {
			invalid = append(invalid, s)
		}
	}
	return valid, invalid
}

// ScopesEqual checks if two scope slices contain the same scopes (order-independent)
func ScopesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aSet := make(map[string]bool, len(a))
	for _, s := range a {
		aSet[s] = true
	}
	for _, s := range b {
		if !aSet[s] {
			return false
		}
	}
	return true
}
