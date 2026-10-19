package fs

import (
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/refreshtokentest"
)

// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestFSRefreshTokenStore_AccessTokenContract(t *testing.T) {
	refreshtokentest.RunAll(t, func(t *testing.T) core.RefreshTokenStore {
		return NewFSRefreshTokenStore(t.TempDir())
	})
}
