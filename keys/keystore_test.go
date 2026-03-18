// Tests for the in-memory KeyStore implementation using the shared keystoretest suite.
package keys_test

import (
	"github.com/panyam/oneauth/keys"
	"testing"
	"github.com/panyam/oneauth/keystoretest"
)

// TestInMemoryKeyStore runs the shared WritableKeyStore test suite against the in-memory implementation.
func TestInMemoryKeyStore(t *testing.T) {
	keystoretest.RunAll(t, func(t *testing.T) keys.KeyStorage {
		return keys.NewInMemoryKeyStore()
	})
}
