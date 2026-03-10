package fs

import (
	"testing"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/keystoretest"
)

func TestFSKeyStore(t *testing.T) {
	keystoretest.RunAll(t, func(t *testing.T) oa.WritableKeyStore {
		dir := t.TempDir()
		return NewFSKeyStore(dir)
	})
}
