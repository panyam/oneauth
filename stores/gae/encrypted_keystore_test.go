package gae

// EncryptedKeyStorage and EncryptedKidStorage bind each ciphertext to its record's client, alg
// and kid, so the backend underneath has to return those exactly as
// written. The shared contract suite, run through the wrapper, checks
// that this backend does. Runs under `make testds`.
//
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option" //nolint:staticcheck // WithCredentialsFile is simpler for test use

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/keystoretest"
	"github.com/panyam/oneauth/kidstoretest"
)

func TestGAEKeyStore_ThroughEncryptedKeyStorage(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE KeyStore tests")
	}
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	ctx := context.Background()
	client, err := datastore.NewClient(ctx, projectID, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	const namespace = "oneauth-encrypted-keystore-test"
	clear := func() {
		ks, _ := client.GetAll(ctx, datastore.NewQuery(KindSigningKey).KeysOnly().Namespace(namespace), nil)
		if len(ks) > 0 {
			_ = client.DeleteMulti(ctx, ks)
		}
	}
	t.Cleanup(clear)

	keystoretest.RunAll(t, func(t *testing.T) keys.KeyStorage {
		clear()
		enc, err := keys.NewEncryptedKeyStorage(NewKeyStore(client, namespace), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		require.NoError(t, err)
		return enc
	})
}

func TestGAEKidStore_ThroughEncryptedKidStorage(t *testing.T) {
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE KidStore tests")
	}
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	ctx := context.Background()
	client, err := datastore.NewClient(ctx, projectID, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	const namespace = "oneauth-encrypted-kidstore-test"
	clear := func() {
		ks, _ := client.GetAll(ctx, datastore.NewQuery(KindKidKey).KeysOnly().Namespace(namespace), nil)
		if len(ks) > 0 {
			_ = client.DeleteMulti(ctx, ks)
		}
	}
	t.Cleanup(clear)

	kidstoretest.RunAll(t, func(t *testing.T) keys.KidStorage {
		clear()
		enc, err := keys.NewEncryptedKidStorage(NewKidStore(client, namespace), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		require.NoError(t, err)
		return enc
	})
}
