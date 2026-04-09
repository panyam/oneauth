package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUnionScopes_Disjoint verifies that UnionScopes returns all elements
// from two non-overlapping scope slices, sorted alphabetically.
//
// See: RFC 6749 §3.3 — scope values are space-delimited, order-independent.
func TestUnionScopes_Disjoint(t *testing.T) {
	result := UnionScopes([]string{"write", "read"}, []string{"admin", "profile"})
	assert.Equal(t, []string{"admin", "profile", "read", "write"}, result)
}

// TestUnionScopes_Overlapping verifies that duplicate scopes appearing in both
// slices are deduplicated in the result.
//
// See: RFC 6749 §3.3 — scope tokens MUST NOT appear more than once.
func TestUnionScopes_Overlapping(t *testing.T) {
	result := UnionScopes([]string{"read", "write"}, []string{"write", "admin"})
	assert.Equal(t, []string{"admin", "read", "write"}, result)
}

// TestUnionScopes_EmptyInputs verifies correct behavior when one or both
// inputs are empty slices.
func TestUnionScopes_EmptyInputs(t *testing.T) {
	// Both empty
	result := UnionScopes([]string{}, []string{})
	assert.Empty(t, result)

	// First empty
	result = UnionScopes([]string{}, []string{"read", "write"})
	assert.Equal(t, []string{"read", "write"}, result)

	// Second empty
	result = UnionScopes([]string{"admin"}, []string{})
	assert.Equal(t, []string{"admin"}, result)
}

// TestUnionScopes_NilInputs verifies correct behavior when one or both
// inputs are nil (should not panic).
func TestUnionScopes_NilInputs(t *testing.T) {
	result := UnionScopes(nil, nil)
	assert.Empty(t, result)

	result = UnionScopes(nil, []string{"read"})
	assert.Equal(t, []string{"read"}, result)

	result = UnionScopes([]string{"write"}, nil)
	assert.Equal(t, []string{"write"}, result)
}

// TestUnionScopes_AlreadySorted verifies that result is always sorted
// regardless of input order.
func TestUnionScopes_AlreadySorted(t *testing.T) {
	result := UnionScopes([]string{"z", "a", "m"}, []string{"b", "y"})
	assert.Equal(t, []string{"a", "b", "m", "y", "z"}, result)
}
