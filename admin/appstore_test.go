// Tests the in-memory AppRegistrationStore against the shared appstoretest
// contract suite. Persistent backends (FS in #166, GORM in #167) reuse the
// same suite from their own packages.
package admin_test

import (
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/appstoretest"
)

// TestInMemoryAppStore verifies that admin.NewInMemoryAppStore satisfies the
// AppRegistrationStore contract.
func TestInMemoryAppStore(t *testing.T) {
	appstoretest.RunAll(t, func(t *testing.T) admin.AppRegistrationStore {
		return admin.NewInMemoryAppStore()
	})
}
