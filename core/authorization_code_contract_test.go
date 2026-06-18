package core_test

import (
	"testing"

	"github.com/panyam/oneauth/authcodetest"
	"github.com/panyam/oneauth/core"
)

// TestInMemoryAuthorizationCodeStore_Contract runs the shared
// AuthorizationCodeStore contract suite against the in-memory backend.
// Each scenario gets a fresh store; Reopen returns the same instance
// since there is no underlying storage to reconnect to.
func TestInMemoryAuthorizationCodeStore_Contract(t *testing.T) {
	authcodetest.RunAll(t, func(t *testing.T) authcodetest.Backend {
		s := core.NewInMemoryAuthorizationCodeStore()
		return authcodetest.Backend{
			Store:  s,
			Reopen: func() core.AuthorizationCodeStore { return s },
		}
	})
}
