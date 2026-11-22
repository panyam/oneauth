//go:build !wasm
// +build !wasm

package gorm

import (
	"testing"

	"github.com/panyam/oneauth/apikeytest"
)

func TestGORMAPIKeyStore_AdminContract(t *testing.T) {
	apikeytest.RunAdmin(t, func(t *testing.T) apikeytest.Backend {
		db := setupTestDB(t)
		return apikeytest.Backend{
			Store:  NewAPIKeyStore(db),
			Reopen: func() apikeytest.Store { return NewAPIKeyStore(db) },
		}
	})
}
