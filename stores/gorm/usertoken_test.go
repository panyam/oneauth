//go:build !wasm
// +build !wasm

package gorm

import (
	"testing"

	"github.com/panyam/oneauth/outbound"
	"github.com/panyam/oneauth/usertokentest"
)

// TestGORMUserTokenStore runs the UserTokenStore contract on SQLite, or
// on PostgreSQL with a real connection pool when ONEAUTH_TEST_PGDB is set
// (make testpg).
func TestGORMUserTokenStore(t *testing.T) {
	usertokentest.RunAll(t, func(t *testing.T) outbound.UserTokenStore {
		return NewUserTokenStore(setupTestDB(t))
	})
}
