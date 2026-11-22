package fs_test

import (
	"testing"

	"github.com/panyam/oneauth/apikeytest"
	"github.com/panyam/oneauth/stores/fs"
)

func TestFSAPIKeyStore_AdminContract(t *testing.T) {
	apikeytest.RunAdmin(t, func(t *testing.T) apikeytest.Backend {
		dir := t.TempDir()
		return apikeytest.Backend{
			Store:  fs.NewFSAPIKeyStore(dir),
			Reopen: func() apikeytest.Store { return fs.NewFSAPIKeyStore(dir) },
		}
	})
}
