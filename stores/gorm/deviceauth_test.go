//go:build !wasm
// +build !wasm

// Tests for the GORM-backed DeviceAuthorizationStore. Runs the shared
// deviceauthtest contract suite against SQLite (default) or PostgreSQL
// when ONEAUTH_TEST_PGDB is set, mirroring the GORMAppStore /
// GORMKeyStore test setup.
package gorm

import (
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/deviceauthtest"
)

// TestGORMDeviceAuthStore_Contract runs the shared
// DeviceAuthorizationStore contract suite against the GORM backend.
// Each scenario gets a fresh database; Reopen constructs a new store
// over the same *gorm.DB so RestartPersists simulates a fresh process
// opening the same database.
func TestGORMDeviceAuthStore_Contract(t *testing.T) {
	deviceauthtest.RunAll(t, func(t *testing.T) deviceauthtest.Backend {
		db := setupTestDB(t)
		return deviceauthtest.Backend{
			Store:  NewDeviceAuthStore(db),
			Reopen: func() core.DeviceAuthorizationStore { return NewDeviceAuthStore(db) },
		}
	})
}
