//go:build !wasm
// +build !wasm

package gorm

import (
	"testing"

	"github.com/panyam/oneauth/channeltest"
)

func TestGORMChannelStore_AdminContract(t *testing.T) {
	channeltest.RunAdmin(t, func(t *testing.T) channeltest.Backend {
		db := setupTestDB(t)
		return channeltest.Backend{
			Store:  NewChannelStore(db),
			Reopen: func() channeltest.Store { return NewChannelStore(db) },
		}
	})
}
