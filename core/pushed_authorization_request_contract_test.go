package core_test

// The in-memory PushedAuthorizationRequestStore runs the shared partest
// contract suite, the same suite every other backend runs. See
// partest/partest.go for what each scenario pins.
//
// See: https://github.com/panyam/oneauth/issues/337

import (
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/partest"
)

func TestInMemoryPushedAuthorizationRequestStore_Contract(t *testing.T) {
	partest.RunAll(t, func(t *testing.T) partest.Backend {
		store := core.NewInMemoryPushedAuthorizationRequestStore()
		return partest.Backend{
			Store:  store,
			Reopen: func() core.PushedAuthorizationRequestStore { return store },
		}
	})
}
