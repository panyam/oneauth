package fs

// Verification and password-reset tokens are stored as hashes, so read
// access to the token directory (a backup, a misconfigured volume) doesn't
// hand out working reset links, and a delete says whether it was the one
// that consumed the token.
//
// See: https://cwe.mitre.org/data/definitions/256.html (plaintext storage)
// See: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/localauth"
)

func TestFSTokenStore_StoresOnlyAHash(t *testing.T) {
	dir := t.TempDir()
	s := NewFSTokenStore(dir)
	ctx := context.Background()
	created, err := s.CreateToken(ctx, &localauth.CreateVerificationTokenRequest{
		Email: "a@example.com", Type: localauth.VerificationTypePasswordReset, ExpiryDuration: time.Hour,
	})
	require.NoError(t, err)
	raw := created.Token.Token
	require.NotEmpty(t, raw)

	require.NoError(t, filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		assert.NotContains(t, path, raw, "the raw token must not be a file name")
		if !info.IsDir() {
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.False(t, strings.Contains(string(data), raw), "the raw token must not be in %s", path)
		}
		return nil
	}))

	got, err := s.GetToken(ctx, &localauth.GetVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.Equal(t, "a@example.com", got.Token.Email)
	assert.Equal(t, raw, got.Token.Token)

	first, err := s.DeleteToken(ctx, &localauth.DeleteVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.True(t, first.Deleted)
	second, err := s.DeleteToken(ctx, &localauth.DeleteVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.False(t, second.Deleted, "only one caller consumes a token")
}
