//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/keystoretest"
	"google.golang.org/api/option" //nolint:staticcheck // WithCredentialsFile is simpler for test use
)

// TestGAEKeyStore runs the shared KeyStore test suite against Google Cloud Datastore.
//
// To run against the Datastore emulator:
//
//	export DATASTORE_EMULATOR_HOST=localhost:8081
//	export DATASTORE_PROJECT_ID=test-project
//	go test -v ./stores/gae/...
//
// To run against a real GCP project:
//
//	export DATASTORE_PROJECT_ID=your-project-id
//	export DATASTORE_CREDENTIALS_FILE=~/path/to/creds.json
//	export DATASTORE_TEST_NAMESPACE=oneauth-test
//	go test -v ./stores/gae/...
func TestGAEKeyStore(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE KeyStore tests")
	}

	namespace := os.Getenv("DATASTORE_TEST_NAMESPACE")
	if namespace == "" {
		namespace = "oneauth-keystore-test"
	}

	ctx := context.Background()
	var opts []option.ClientOption

	credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE")
	if credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}

	client, err := datastore.NewClient(ctx, projectID, opts...)
	if err != nil {
		t.Fatalf("Failed to create Datastore client: %v", err)
	}
	defer client.Close()

	// Cleanup: delete all SigningKey entities in this namespace after tests
	t.Cleanup(func() {
		q := datastore.NewQuery(KindSigningKey).KeysOnly().Namespace(namespace)
		keys, err := client.GetAll(ctx, q, nil)
		if err != nil {
			t.Logf("Cleanup warning: failed to query keys: %v", err)
			return
		}
		if len(keys) > 0 {
			if err := client.DeleteMulti(ctx, keys); err != nil {
				t.Logf("Cleanup warning: failed to delete keys: %v", err)
			}
		}
	})

	keystoretest.RunAll(t, func(t *testing.T) oa.WritableKeyStore {
		// Clean before each sub-test
		q := datastore.NewQuery(KindSigningKey).KeysOnly().Namespace(namespace)
		keys, _ := client.GetAll(ctx, q, nil)
		if len(keys) > 0 {
			client.DeleteMulti(ctx, keys)
		}
		return NewKeyStore(client, namespace)
	})
}
