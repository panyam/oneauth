//go:build !wasm
// +build !wasm

package gae

import (
	"testing"

	"github.com/panyam/oneauth/consenttest"
	"github.com/panyam/oneauth/core"
)

func TestGAEConsentStore_Contract(t *testing.T) {
	const ns = "oneauth-consent-test"
	client, cleanup := emulatorClient(t, KindConsent, ns)
	consenttest.RunAll(t, func(t *testing.T) consenttest.Backend {
		cleanup()
		return consenttest.Backend{
			Store:  NewConsentStore(client, ns),
			Reopen: func() core.ConsentStore { return NewConsentStore(client, ns) },
		}
	})
}
