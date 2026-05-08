//go:build !wasm
// +build !wasm

// Tests for the GORM-backed AppRegistrationStore — runs the shared
// appstoretest contract suite against SQLite (default) or PostgreSQL when
// ONEAUTH_TEST_PGDB is set, mirroring the GORMKeyStore test setup.
package gorm

import (
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/appstoretest"
)

// TestGORMAppStore runs the shared AppRegistrationStore contract suite
// against the GORM-backed implementation. Each sub-test gets a fresh DB
// connection (and, for Postgres, an isolated schema) so state cannot leak
// between cases.
func TestGORMAppStore(t *testing.T) {
	appstoretest.RunAll(t, func(t *testing.T) admin.AppRegistrationStore {
		return NewAppStore(setupTestDB(t))
	})
}
