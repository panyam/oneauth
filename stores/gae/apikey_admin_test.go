//go:build !wasm
// +build !wasm

package gae

import (
	"testing"

	"github.com/panyam/oneauth/apikeytest"
)

func TestGAEAPIKeyStore_AdminContract(t *testing.T) {
	const ns = "oneauth-apikey-admin-test"
	client, cleanup := emulatorClient(t, KindAPIKey, ns)
	apikeytest.RunAdmin(t, func(t *testing.T) apikeytest.Backend {
		cleanup()
		return apikeytest.Backend{
			Store:  NewAPIKeyStore(client, ns),
			Reopen: func() apikeytest.Store { return NewAPIKeyStore(client, ns) },
		}
	})
}
