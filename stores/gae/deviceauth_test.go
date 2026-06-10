//go:build !wasm
// +build !wasm

// Tests for the Datastore-backed DeviceAuthorizationStore. Runs the
// shared deviceauthtest contract suite. Same env contract as the other
// GAE backend tests — skips unless DATASTORE_PROJECT_ID is set, so plain
// `go test ./...` on a dev machine without the emulator running doesn't
// spuriously fail.
//
// To run against the Datastore emulator:
//
//	make upds && make testds
//
// Or manually:
//
//	export DATASTORE_EMULATOR_HOST=localhost:8081
//	export DATASTORE_PROJECT_ID=test-project
//	GOWORK=off go test -v ./stores/gae/...

package gae

import (
	"context"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/deviceauthtest"
	"google.golang.org/api/option" //nolint:staticcheck // WithCredentialsFile is simpler for test use
)

// TestGAEDeviceAuthStore_Contract runs the shared
// DeviceAuthorizationStore contract suite against the GAE Datastore
// backend. Each scenario runs against a freshly-cleaned namespace; Reopen
// constructs a new store over the same client + namespace so
// RestartPersists simulates a fresh process opening the same Datastore.
func TestGAEDeviceAuthStore_Contract(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE DeviceAuthStore tests")
	}
	namespace := os.Getenv("DATASTORE_TEST_NAMESPACE")
	if namespace == "" {
		namespace = "oneauth-deviceauth-test"
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
	t.Cleanup(func() { _ = client.Close() })

	cleanup := func() {
		q := datastore.NewQuery(KindDeviceAuthorization).KeysOnly().Namespace(namespace)
		keys, err := client.GetAll(ctx, q, nil)
		if err != nil {
			t.Logf("cleanup query: %v", err)
			return
		}
		if len(keys) > 0 {
			if err := client.DeleteMulti(ctx, keys); err != nil {
				t.Logf("cleanup delete: %v", err)
			}
		}
	}
	t.Cleanup(cleanup)

	deviceauthtest.RunAll(t, func(t *testing.T) deviceauthtest.Backend {
		cleanup() // fresh state per sub-test
		return deviceauthtest.Backend{
			Store:  NewDeviceAuthStore(client, namespace),
			Reopen: func() core.DeviceAuthorizationStore { return NewDeviceAuthStore(client, namespace) },
		}
	})
}
