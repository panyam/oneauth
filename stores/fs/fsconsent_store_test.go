package fs_test

import (
	"testing"

	"github.com/panyam/oneauth/consenttest"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/stores/fs"
)

func TestFSConsentStore_Contract(t *testing.T) {
	consenttest.RunAll(t, func(t *testing.T) consenttest.Backend {
		dir := t.TempDir()
		return consenttest.Backend{
			Store:  fs.NewFSConsentStore(dir),
			Reopen: func() core.ConsentStore { return fs.NewFSConsentStore(dir) },
		}
	})
}
