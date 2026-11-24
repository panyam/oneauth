package fs_test

import (
	"testing"

	"github.com/panyam/oneauth/channeltest"
	"github.com/panyam/oneauth/stores/fs"
)

func TestFSChannelStore_AdminContract(t *testing.T) {
	channeltest.RunAdmin(t, func(t *testing.T) channeltest.Backend {
		dir := t.TempDir()
		return channeltest.Backend{
			Store:  fs.NewFSChannelStore(dir),
			Reopen: func() channeltest.Store { return fs.NewFSChannelStore(dir) },
		}
	})
}
