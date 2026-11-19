//go:build !wasm
// +build !wasm

// The GORM ConsentStore runs the shared consenttest contract suite against
// SQLite (default) or PostgreSQL when ONEAUTH_TEST_PGDB is set, mirroring
// the PAR store setup.
package gorm

import (
	"testing"

	"github.com/panyam/oneauth/consenttest"
	"github.com/panyam/oneauth/core"
)

func TestGORMConsentStore_Contract(t *testing.T) {
	consenttest.RunAll(t, func(t *testing.T) consenttest.Backend {
		db := setupTestDB(t)
		return consenttest.Backend{
			Store:  NewConsentStore(db),
			Reopen: func() core.ConsentStore { return NewConsentStore(db) },
		}
	})
}
