package keys_test

// Runs the shared KidStorage conformance suite against the in-memory
// KidStore. The same suite also runs against the FS, GORM, and GAE
// backends in their respective test files.

import (
	"testing"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/kidstoretest"
)

func TestInMemoryKidStoreConformance(t *testing.T) {
	kidstoretest.RunAll(t, func(t *testing.T) keys.KidStorage {
		return keys.NewKidStore()
	})
}
