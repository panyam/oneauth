//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/outbound"
	"github.com/panyam/oneauth/usertokentest"
	"google.golang.org/api/option" //nolint:staticcheck // WithCredentialsFile is simpler for test use
)

// TestGAEUserTokenStore runs the UserTokenStore contract against
// Datastore. Skips unless DATASTORE_PROJECT_ID is set; make testds runs it
// on the emulator, as CI's gae job does.
func TestGAEUserTokenStore(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE UserTokenStore tests")
	}
	namespace := "oneauth-usertoken-test"
	ctx := context.Background()
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	client, err := datastore.NewClient(ctx, projectID, opts...)
	if err != nil {
		t.Fatalf("Failed to create Datastore client: %v", err)
	}
	defer client.Close()

	cleanup := func() {
		q := datastore.NewQuery(KindUserToken).KeysOnly().Namespace(namespace)
		keys, err := client.GetAll(ctx, q, nil)
		if err != nil {
			t.Logf("Cleanup warning: %v", err)
			return
		}
		if len(keys) > 0 {
			if err := client.DeleteMulti(ctx, keys); err != nil {
				t.Logf("Cleanup warning: %v", err)
			}
		}
	}
	t.Cleanup(cleanup)

	usertokentest.RunAll(t, func(t *testing.T) outbound.UserTokenStore {
		cleanup()
		return NewUserTokenStore(client, namespace)
	})
}
