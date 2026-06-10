package core_test

import (
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/deviceauthtest"
)

// TestInMemoryDeviceAuthStore_Contract runs the shared
// DeviceAuthorizationStore contract suite against the in-memory backend.
// Each scenario gets a fresh store; Reopen returns the same instance
// since there is no underlying storage to reconnect to.
func TestInMemoryDeviceAuthStore_Contract(t *testing.T) {
	deviceauthtest.RunAll(t, func(t *testing.T) deviceauthtest.Backend {
		s := core.NewInMemoryDeviceAuthorizationStore()
		return deviceauthtest.Backend{
			Store:  s,
			Reopen: func() core.DeviceAuthorizationStore { return s },
		}
	})
}
