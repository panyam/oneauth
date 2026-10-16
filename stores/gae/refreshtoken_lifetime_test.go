package gae

// Rotation keeps the family's expiry, so refreshing can't keep a family
// alive forever. Runs under `make testds`.
//
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"

	"github.com/panyam/oneauth/core"
)

func TestGAERefreshTokenStore_RotationKeepsTheFamilyExpiry(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE RefreshTokenStore tests")
	}
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	ctx := context.Background()
	client, err := datastore.NewClient(ctx, projectID, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	store := NewRefreshTokenStore(client, "oneauth-refresh-lifetime-test")

	created, err := store.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "c"})
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	rotated, err := store.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: created.Token.Token})
	require.NoError(t, err)
	require.WithinDuration(t, created.Token.ExpiresAt, rotated.Token.ExpiresAt, 5*time.Millisecond)

	got, err := store.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: rotated.Token.Token})
	require.NoError(t, err)
	require.WithinDuration(t, created.Token.ExpiresAt, got.Token.ExpiresAt, 5*time.Millisecond, "stored expiry")
}
