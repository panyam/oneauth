package fs_test

import (
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/deviceauthtest"
	"github.com/panyam/oneauth/stores/fs"
)

// TestFSDeviceAuthStore_Contract runs the shared
// DeviceAuthorizationStore contract suite against the filesystem backend.
// Each scenario gets a fresh tempdir; Reopen constructs a new store
// rooted at that same dir so RestartPersists simulates a process restart.
func TestFSDeviceAuthStore_Contract(t *testing.T) {
	deviceauthtest.RunAll(t, func(t *testing.T) deviceauthtest.Backend {
		dir := t.TempDir()
		return deviceauthtest.Backend{
			Store:  fs.NewFSDeviceAuthorizationStore(dir),
			Reopen: func() core.DeviceAuthorizationStore { return fs.NewFSDeviceAuthorizationStore(dir) },
		}
	})
}
