//go:build !wasm
// +build !wasm

// The GORM PushedAuthorizationRequestStore runs the shared partest contract
// suite against SQLite (default) or PostgreSQL when ONEAUTH_TEST_PGDB is
// set, mirroring the authcode and device-auth store setups.
//
// See: https://github.com/panyam/oneauth/issues/337
package gorm

import (
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/partest"
)

func TestGORMPushedAuthorizationRequestStore_Contract(t *testing.T) {
	partest.RunAll(t, func(t *testing.T) partest.Backend {
		db := setupTestDB(t)
		return partest.Backend{
			Store:  NewPushedAuthorizationRequestStore(db),
			Reopen: func() core.PushedAuthorizationRequestStore { return NewPushedAuthorizationRequestStore(db) },
		}
	})
}
