package gorm

// Verification and password-reset tokens are stored as hashes, and a delete
// says whether it consumed the token.
//
// See: https://cwe.mitre.org/data/definitions/256.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/localauth"
)

func TestGORMTokenStore_StoresOnlyAHash(t *testing.T) {
	db := setupTestDB(t)
	s := NewTokenStore(db)
	ctx := context.Background()
	created, err := s.CreateToken(ctx, &localauth.CreateVerificationTokenRequest{
		Email: "a@example.com", Type: localauth.VerificationTypePasswordReset, ExpiryDuration: time.Hour,
	})
	require.NoError(t, err)
	raw := created.Token.Token

	var stored []string
	require.NoError(t, db.Model(&VerificationTokenModel{}).Pluck("token", &stored).Error)
	require.Len(t, stored, 1)
	assert.NotEqual(t, raw, stored[0], "the raw token must not be stored")

	got, err := s.GetToken(ctx, &localauth.GetVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.Equal(t, "a@example.com", got.Token.Email)
	assert.Equal(t, raw, got.Token.Token)

	first, err := s.DeleteToken(ctx, &localauth.DeleteVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.True(t, first.Deleted)
	second, err := s.DeleteToken(ctx, &localauth.DeleteVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.False(t, second.Deleted)
}
