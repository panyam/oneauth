package gae

// Runs under `make testds`.

import (
	"context"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/refreshtokentest"
)

// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestGAERefreshTokenStore_AccessTokenContract(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE RefreshTokenStore tests")
	}
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	client, err := datastore.NewClient(context.Background(), projectID, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	refreshtokentest.RunAll(t, func(t *testing.T) core.RefreshTokenStore {
		return NewRefreshTokenStore(client, "oneauth-refresh-access-test")
	})
}
