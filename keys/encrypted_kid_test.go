package keys_test

// EncryptedKidStorage, issue 88's "Key Management" walk: retired keys kept
// for their grace period are secrets too, so a persistent KidStorage gets
// the same encryption at rest as the KeyStorage that held them before
// rotation.
//
// See: https://cwe.mitre.org/data/definitions/312.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/kidstoretest"
)

var retiredSecret = []byte("retired-hmac-secret-32-bytes-ok!")

func newEncryptedKid(t *testing.T, inner keys.KidStorage, master string) *keys.EncryptedKidStorage {
	t.Helper()
	enc, err := keys.NewEncryptedKidStorage(inner, master)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestEncryptedKidStorage_Contract(t *testing.T) {
	kidstoretest.RunAll(t, func(t *testing.T) keys.KidStorage {
		return newEncryptedKid(t, keys.NewKidStore(), testMasterKey)
	})
}

func TestEncryptedKidStorage_RetiredSecretIsEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	inner := keys.NewKidStore()
	enc := newEncryptedKid(t, inner, testMasterKey)
	if _, err := enc.Add(ctx, &keys.AddKidRequest{Kid: "old", Key: retiredSecret, Algorithm: "HS256", ClientID: "app"}); err != nil {
		t.Fatal(err)
	}

	raw, err := inner.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "old"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw.Record.Key.([]byte), retiredSecret) {
		t.Fatal("retired secret stored in plaintext")
	}
	got, err := enc.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "old"})
	if err != nil || !bytes.Equal(got.Record.Key.([]byte), retiredSecret) {
		t.Fatalf("read back: %v, %v", got, err)
	}

	if _, err := newEncryptedKid(t, inner, randomMasterKey(t)).GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "old"}); !errors.Is(err, keys.ErrKeyDecrypt) {
		t.Fatalf("wrong master key: got %v, want ErrKeyDecrypt", err)
	}
}

func TestEncryptedKidStorage_PlaintextNeedsTheLegacyOption(t *testing.T) {
	ctx := context.Background()
	inner := keys.NewKidStore()
	if _, err := inner.Add(ctx, &keys.AddKidRequest{Kid: "old", Key: retiredSecret, Algorithm: "HS256", ClientID: "app"}); err != nil {
		t.Fatal(err)
	}
	enc := newEncryptedKid(t, inner, testMasterKey)
	if _, err := enc.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "old"}); !errors.Is(err, keys.ErrKeyDecrypt) {
		t.Fatalf("plaintext retired secret: got %v, want ErrKeyDecrypt", err)
	}
	enc.AllowLegacyPlaintext = true
	if got, err := enc.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "old"}); err != nil || !bytes.Equal(got.Record.Key.([]byte), retiredSecret) {
		t.Fatalf("with AllowLegacyPlaintext: %v, %v", got, err)
	}
}
