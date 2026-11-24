//go:build !wasm
// +build !wasm

package gae

import (
	"testing"

	"github.com/panyam/oneauth/channeltest"
)

func TestGAEChannelStore_AdminContract(t *testing.T) {
	const ns = "oneauth-channel-admin-test"
	client, cleanup := emulatorClient(t, KindChannel, ns)
	channeltest.RunAdmin(t, func(t *testing.T) channeltest.Backend {
		cleanup()
		return channeltest.Backend{
			Store:  NewChannelStore(client, ns),
			Reopen: func() channeltest.Store { return NewChannelStore(client, ns) },
		}
	})
}
