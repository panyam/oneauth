package main

// The reference server keeps rotated keys for their grace period in a kid
// store on the key store's backend, encrypted under the same master key.
//
// See: https://cwe.mitre.org/data/definitions/312.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/keys"
)

func TestKidStore_RetiredKeysAreEncryptedOnDisk(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{KeyStore: KeyStoreConfig{Type: "fs", FS: FSConfig{Path: dir}, MasterKey: migrationMasterKey}}
	store, err := buildKidStore(cfg, nil)
	require.NoError(t, err)

	secret := []byte("retired-secret-that-is-32-bytes!")
	_, err = store.Add(context.Background(), &keys.AddKidRequest{Kid: "old", Key: secret, Algorithm: "HS256", ClientID: "app", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	got, err := store.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "old"})
	require.NoError(t, err)
	assert.Equal(t, secret, got.Record.Key)

	files := 0
	_ = filepath.Walk(filepath.Join(dir, "kids"), func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			files++
			b, _ := os.ReadFile(p)
			assert.False(t, bytes.Contains(b, secret), "retired secret in plaintext at %s", p)
		}
		return nil
	})
	assert.Positive(t, files, "the kid store writes under <key store path>/kids")
}

func TestKidStore_UnknownTypeIsAnError(t *testing.T) {
	_, err := buildKidStore(&Config{KeyStore: KeyStoreConfig{Type: "nope"}}, nil)
	assert.Error(t, err)
}
