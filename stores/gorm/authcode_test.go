//go:build !wasm
// +build !wasm

// Tests for the GORM-backed AuthorizationCodeStore. Runs the shared
// authcodetest contract suite against SQLite (default) or PostgreSQL
// when ONEAUTH_TEST_PGDB is set, mirroring the GORMAppStore /
// GORMDeviceAuthStore test setup.
package gorm

import (
	"testing"

	"github.com/panyam/oneauth/authcodetest"
	"github.com/panyam/oneauth/core"
)

// TestGORMAuthorizationCodeStore_Contract runs the shared
// AuthorizationCodeStore contract suite against the GORM backend.
// Each scenario gets a fresh database; Reopen constructs a new store
// over the same *gorm.DB so RestartPersists simulates a fresh process
// opening the same database.
func TestGORMAuthorizationCodeStore_Contract(t *testing.T) {
	authcodetest.RunAll(t, func(t *testing.T) authcodetest.Backend {
		db := setupTestDB(t)
		return authcodetest.Backend{
			Store:  NewAuthorizationCodeStore(db),
			Reopen: func() core.AuthorizationCodeStore { return NewAuthorizationCodeStore(db) },
		}
	})
}
