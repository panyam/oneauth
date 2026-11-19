//go:build windows

package fs

// Windows refuses <>:"|? and * in file names, so osFileName folds them into
// "_" there. Folding can map two keys to one file, and the collision checks
// must still keep each record with its own key.
//
// See: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
// See: https://github.com/panyam/oneauth/issues/502

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
)

func TestFSIdentityStore_WindowsReservedCharacters(t *testing.T) {
	ctx := context.Background()
	s := NewFSIdentityStore(t.TempDir())
	for _, v := range []string{"alice@example.com", `"a|b?"@example.com`} {
		_, err := s.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: &accounts.Identity{Type: "email", Value: v, UserID: v}})
		require.NoError(t, err, v)
		got, err := s.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: v})
		require.NoError(t, err, v)
		assert.Equal(t, v, got.Identity.UserID)
	}
}

// "email:a_b" and "email:a|b" both fold to email_a_b.json on Windows.
func TestFSIdentityStore_WindowsFoldedKeysCollide(t *testing.T) {
	ctx := context.Background()
	s := NewFSIdentityStore(t.TempDir())
	_, err := s.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: &accounts.Identity{Type: "email", Value: "a_b@example.com", UserID: "victim"}})
	require.NoError(t, err)

	_, err = s.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: &accounts.Identity{Type: "email", Value: "a|b@example.com", UserID: "attacker"}})
	assert.ErrorIs(t, err, ErrKeyCollision)

	got, err := s.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: "a_b@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "victim", got.Identity.UserID)
}

func TestSafeName_WindowsReservedCharacters(t *testing.T) {
	got, err := safeName(`a<b>c"d|e?f*g`)
	require.NoError(t, err)
	assert.Equal(t, "a_b_c_d_e_f_g", got)
}
