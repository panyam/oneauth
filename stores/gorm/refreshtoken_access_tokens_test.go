//go:build !wasm
// +build !wasm

package gorm

import (
	"os"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/refreshtokentest"
)

// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestGORMRefreshTokenStore_AccessTokenContract(t *testing.T) {
	refreshtokentest.RunAll(t, func(t *testing.T) core.RefreshTokenStore {
		db := setupTestDB(t)
		if os.Getenv("ONEAUTH_TEST_PGDB") == "" {
			// Every connection to sqlite's :memory: opens its own empty
			// database, so the concurrent scenario needs the one that
			// was migrated. Postgres runs it with a real pool.
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			sqlDB.SetMaxOpenConns(1)
		}
		return NewRefreshTokenStore(db)
	})
}
