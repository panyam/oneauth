package keys_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/panyam/oneauth/keys"
)

const sealerMaster = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestSealer_RoundTripAndFreshNonce(t *testing.T) {
	s, err := keys.NewSealer(sealerMaster, "test-purpose")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Seal([]byte("secret"), []byte("rec-1"))
	b, _ := s.Seal([]byte("secret"), []byte("rec-1"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical")
	}
	got, err := s.Open(a, []byte("rec-1"))
	if err != nil || string(got) != "secret" {
		t.Fatalf("Open: %q, %v", got, err)
	}
}

// See: https://cwe.mitre.org/data/definitions/323.html
func TestSealer_PurposeSeparatesKeys(t *testing.T) {
	a, _ := keys.NewSealer(sealerMaster, "purpose-a")
	b, _ := keys.NewSealer(sealerMaster, "purpose-b")
	sealed, _ := a.Seal([]byte("secret"), nil)
	if _, err := b.Open(sealed, nil); !errors.Is(err, keys.ErrSealedOpen) {
		t.Fatalf("opened under another purpose: %v", err)
	}
}

func TestSealer_RefusesWrongAADTamperAndPlaintext(t *testing.T) {
	s, _ := keys.NewSealer(sealerMaster, "p")
	sealed, _ := s.Seal([]byte("secret"), []byte("rec-1"))
	if _, err := s.Open(sealed, []byte("rec-2")); !errors.Is(err, keys.ErrSealedOpen) {
		t.Errorf("wrong AAD: %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := s.Open(tampered, []byte("rec-1")); !errors.Is(err, keys.ErrSealedOpen) {
		t.Errorf("tampered: %v", err)
	}
	if _, err := s.Open([]byte("secret"), nil); !errors.Is(err, keys.ErrSealedOpen) {
		t.Errorf("plaintext: %v", err)
	}
	if _, err := s.Open([]byte("oaenc1:x"), nil); !errors.Is(err, keys.ErrSealedOpen) {
		t.Errorf("truncated: %v", err)
	}
}

// Records EncryptedKeyStorage already wrote must keep opening, so its key
// derivation can't move. A Sealer under KeyStorePurpose opens them.
func TestSealer_KeyStorePurposeOpensKeyStoreRecords(t *testing.T) {
	inner := keys.NewInMemoryKeyStore()
	ks, err := keys.NewEncryptedKeyStorage(inner, sealerMaster)
	if err != nil {
		t.Fatal(err)
	}
	rec := &keys.KeyRecord{ClientID: "c", Key: []byte("hmac-secret-32-bytes-long-000000"), Algorithm: "HS256"}
	if _, err := ks.PutKey(t.Context(), &keys.PutKeyRequest{Record: rec}); err != nil {
		t.Fatal(err)
	}
	stored, _ := inner.GetKey(t.Context(), &keys.GetKeyRequest{ClientID: "c"})
	s, _ := keys.NewSealer(sealerMaster, keys.KeyStorePurpose)
	aad := []byte("oneauth-key\x00c\x00HS256\x00" + stored.Record.Kid)
	if got, err := s.Open(stored.Record.Key.([]byte), aad); err != nil || string(got) != "hmac-secret-32-bytes-long-000000" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNewSealer_Validation(t *testing.T) {
	for _, tc := range []struct{ key, purpose string }{
		{sealerMaster, ""},
		{"abcd", "p"},
		{"zz" + sealerMaster[2:], "p"},
	} {
		if _, err := keys.NewSealer(tc.key, tc.purpose); err == nil {
			t.Errorf("NewSealer(%q, %q) accepted", tc.key, tc.purpose)
		}
	}
}
