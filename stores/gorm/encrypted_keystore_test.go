//go:build !wasm
// +build !wasm

package gorm

// EncryptedKeyStorage binds each ciphertext to its record's client, alg
// and kid, so the backend underneath has to return those exactly as
// written. The shared contract suite, run through the wrapper, checks
// that this backend does.
//
// See: https://github.com/panyam/oneauth/issues/88

import (
	"testing"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/keystoretest"
)

const encryptedContractMasterKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestGORMKeyStore_ThroughEncryptedKeyStorage(t *testing.T) {
	keystoretest.RunAll(t, func(t *testing.T) keys.KeyStorage {
		enc, err := keys.NewEncryptedKeyStorage(NewKeyStore(setupTestDB(t)), encryptedContractMasterKey)
		if err != nil {
			t.Fatal(err)
		}
		return enc
	})
}
