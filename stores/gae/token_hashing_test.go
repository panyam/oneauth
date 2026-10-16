package gae

// Verification and password-reset tokens are stored under a hash, and a
// delete says whether it consumed the token. Runs under `make testds`.
//
// See: https://cwe.mitre.org/data/definitions/256.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"

	"github.com/panyam/oneauth/localauth"
)

func TestGAETokenStore_StoresOnlyAHash(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE TokenStore tests")
	}
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	ctx := context.Background()
	client, err := datastore.NewClient(ctx, projectID, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	s := NewTokenStore(client, "oneauth-token-hash-test")

	created, err := s.CreateToken(ctx, &localauth.CreateVerificationTokenRequest{
		Email: "a@example.com", Type: localauth.VerificationTypePasswordReset, ExpiryDuration: time.Hour,
	})
	require.NoError(t, err)
	raw := created.Token.Token

	var probe VerificationTokenEntity
	err = client.Get(ctx, s.namespacedKey(KindAuthToken, raw), &probe)
	assert.ErrorIs(t, err, datastore.ErrNoSuchEntity, "nothing may be stored under the raw token")

	got, err := s.GetToken(ctx, &localauth.GetVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.Equal(t, "a@example.com", got.Token.Email)

	first, err := s.DeleteToken(ctx, &localauth.DeleteVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.True(t, first.Deleted)
	second, err := s.DeleteToken(ctx, &localauth.DeleteVerificationTokenRequest{Token: raw})
	require.NoError(t, err)
	assert.False(t, second.Deleted)
}
