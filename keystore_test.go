// Tests for the in-memory KeyStore implementation using the shared keystoretest suite.
package oneauth_test

import (
	"testing"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/keystoretest"
)

// TestInMemoryKeyStore runs the shared WritableKeyStore test suite against the in-memory implementation.
func TestInMemoryKeyStore(t *testing.T) {
	keystoretest.RunAll(t, func(t *testing.T) oa.KeyStorage {
		return oa.NewInMemoryKeyStore()
	})
}
