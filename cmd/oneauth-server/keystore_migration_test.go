package main

// Turning on key encryption over a store that already holds plaintext
// secrets: without key_store.migrate_legacy those records stop resolving
// (they could have been planted), and with it the server encrypts them at
// startup.
//
// See: https://cwe.mitre.org/data/definitions/311.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/keys"
	fsstore "github.com/panyam/oneauth/stores/fs"
)

const migrationMasterKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestKeyStore_MigrateLegacyEncryptsPlaintextAtStartup(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("legacy-plaintext-secret-32-bytes")
	_, err := fsstore.NewFSKeyStore(dir).PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app-1", Key: secret, Algorithm: "HS256"}})
	require.NoError(t, err)

	cfg := &Config{KeyStore: KeyStoreConfig{Type: "fs", FS: FSConfig{Path: dir}, MasterKey: migrationMasterKey}}
	store, _, err := buildKeyStore(cfg)
	require.NoError(t, err)
	_, err = store.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: "app-1"})
	assert.True(t, errors.Is(err, keys.ErrKeyDecrypt), "plaintext without migrate_legacy: %v", err)

	cfg.KeyStore.MigrateLegacy = true
	store, _, err = buildKeyStore(cfg)
	require.NoError(t, err)
	got, err := store.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: "app-1"})
	require.NoError(t, err)
	assert.Equal(t, secret, got.Record.Key)

	onDisk := false
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			onDisk = onDisk || bytes.Contains(b, secret)
		}
		return nil
	})
	assert.False(t, onDisk, "the secret is no longer on disk in plaintext")
}
