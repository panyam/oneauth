package fs

// RevokeAPIKey reports a key that doesn't exist as core.ErrAPIKeyNotFound
// in every bundled store, so an admin action on a stale key ID can't
// look like it succeeded (issue 526).
// See: https://github.com/panyam/oneauth/issues/526

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

func TestAPIKeyStore_RevokeReportsAMissingKey(t *testing.T) {
	ctx := context.Background()
	s := NewFSAPIKeyStore(t.TempDir())
	created, err := s.CreateAPIKey(ctx, &core.CreateAPIKeyRequest{Subject: "alice", Name: "ci"})
	require.NoError(t, err)

	_, err = s.RevokeAPIKey(ctx, &core.RevokeAPIKeyRequest{KeyID: created.APIKey.KeyID})
	require.NoError(t, err)
	got, err := s.GetAPIKeyByID(ctx, &core.GetAPIKeyByIDRequest{KeyID: created.APIKey.KeyID})
	require.NoError(t, err)
	assert.True(t, got.APIKey.Revoked)

	_, err = s.RevokeAPIKey(ctx, &core.RevokeAPIKeyRequest{KeyID: "oa_does_not_exist"})
	assert.True(t, errors.Is(err, core.ErrAPIKeyNotFound), "got %v", err)
}
