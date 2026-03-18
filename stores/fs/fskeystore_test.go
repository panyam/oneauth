package fs

// Tests for the filesystem-based WritableKeyStore implementation.

import (
	"testing"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/keystoretest"
)

// TestFSKeyStore runs the shared WritableKeyStore test suite against the filesystem-backed implementation.
func TestFSKeyStore(t *testing.T) {
	keystoretest.RunAll(t, func(t *testing.T) keys.KeyStorage {
		dir := t.TempDir()
		return NewFSKeyStore(dir)
	})
}
