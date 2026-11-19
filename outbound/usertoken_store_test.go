package outbound_test

import (
	"testing"

	"github.com/panyam/oneauth/outbound"
	"github.com/panyam/oneauth/usertokentest"
)

func TestMemoryUserTokenStore_Contract(t *testing.T) {
	usertokentest.RunAll(t, func(t *testing.T) outbound.UserTokenStore {
		return outbound.NewMemoryUserTokenStore()
	})
}
