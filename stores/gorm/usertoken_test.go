//go:build !wasm
// +build !wasm

package gorm

import (
	"os"
	"testing"

	"github.com/panyam/oneauth/outbound"
	"github.com/panyam/oneauth/usertokentest"
)

// TestGORMUserTokenStore runs the UserTokenStore contract on SQLite, or
// on PostgreSQL with a real connection pool when ONEAUTH_TEST_PGDB is set
// (make testpg). SQLite gets one connection, since each pooled ":memory:"
// connection opens its own empty database.
func TestGORMUserTokenStore(t *testing.T) {
	usertokentest.RunAll(t, func(t *testing.T) outbound.UserTokenStore {
		db := setupTestDB(t)
		if os.Getenv("ONEAUTH_TEST_PGDB") == "" {
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			sqlDB.SetMaxOpenConns(1)
		}
		return NewUserTokenStore(db)
	})
}
