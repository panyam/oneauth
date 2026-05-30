//go:build !wasm
// +build !wasm

// Tests for the Google App Engine Datastore-based AppRegistrationStore implementation.

package gae

import (
	"context"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/appstoretest"
	"github.com/panyam/oneauth/core"
	"google.golang.org/api/option" //nolint:staticcheck // WithCredentialsFile is simpler for test use
)

// TestGAEAppStore runs the shared AppRegistrationStore conformance suite
// against Google Cloud Datastore. Skips unless DATASTORE_PROJECT_ID is set —
// same env contract as TestGAEKeyStore and TestGAEKidStore.
//
// To run against the Datastore emulator:
//
//	make upds && make testds
//
// Or manually:
//
//	export DATASTORE_EMULATOR_HOST=localhost:8081
//	export DATASTORE_PROJECT_ID=test-project
//	go test -v ./stores/gae/...
func TestGAEAppStore(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE AppStore tests")
	}

	namespace := os.Getenv("DATASTORE_TEST_NAMESPACE")
	if namespace == "" {
		namespace = "oneauth-appstore-test"
	}

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
		q := datastore.NewQuery(KindAppRegistration).KeysOnly().Namespace(namespace)
		dsKeys, err := client.GetAll(ctx, q, nil)
		if err != nil {
			t.Logf("Cleanup warning: failed to query app entities: %v", err)
			return
		}
		if len(dsKeys) > 0 {
			if err := client.DeleteMulti(ctx, dsKeys); err != nil {
				t.Logf("Cleanup warning: failed to delete app entities: %v", err)
			}
		}
	}
	t.Cleanup(cleanup)

	appstoretest.RunAll(t, func(t *testing.T) core.AppRegistrationStore {
		cleanup() // fresh state per sub-test
		return NewAppStore(client, namespace)
	})
}
