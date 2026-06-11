package sshkeys_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/sshkeys"
	"golang.org/x/crypto/ssh"
)

const testMasterKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestGenerateEd25519_PublicSideParses(t *testing.T) {
	pubLine, _, err := sshkeys.GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
	}
	if pubKey.Type() != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %q, want %q", pubKey.Type(), ssh.KeyAlgoED25519)
	}
}

func TestGenerateEd25519_PrivateSideParses(t *testing.T) {
	_, privPEM, err := sshkeys.GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	if _, err := ssh.ParsePrivateKey(privPEM); err != nil {
		t.Fatalf("ssh.ParsePrivateKey: %v", err)
	}
}

func TestGenerateEd25519_PEMHeaderTriggersEncryption(t *testing.T) {
	_, privPEM, err := sshkeys.GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatal("private output is not a PEM block")
	}
	if block.Type != "OPENSSH PRIVATE KEY" {
		t.Errorf("PEM type = %q, want OPENSSH PRIVATE KEY (EncryptedKeyStorage matches on 'PRIVATE' substring)", block.Type)
	}
}

// TestGenerateEd25519_PublicAndPrivateMatch is the cross-check that the
// returned public and private halves describe the same keypair — the
// private key's derived public must marshal identically to the standalone
// authorized_keys line.
func TestGenerateEd25519_PublicAndPrivateMatch(t *testing.T) {
	pubLine, privPEM, err := sshkeys.GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	pubFromLine, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if !bytes.Equal(pubFromLine.Marshal(), signer.PublicKey().Marshal()) {
		t.Error("public key derived from private does not match standalone public output")
	}
}

func TestGenerateEd25519_FingerprintFormat(t *testing.T) {
	pubLine, _, err := sshkeys.GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	fp := ssh.FingerprintSHA256(pubKey)
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint should start with SHA256:, got %q", fp)
	}
	// base64-no-pad SHA256 is 43 chars; "SHA256:" prefix is 7 chars.
	if got, want := len(fp), len("SHA256:")+43; got != want {
		t.Errorf("fingerprint length = %d, want %d (%q)", got, want, fp)
	}
}

// TestGenerateEd25519_EncryptedStorageRoundTrip is the load-bearing
// integration test for issue 248: a sshkeys-generated private PEM
// persisted via EncryptedKeyStorage must land as ciphertext (not a PEM
// block) in the inner store, and a subsequent GetKey must return the
// original PEM bytes intact. This proves the two halves of the issue
// (encryption widening + sshkeys submodule) compose correctly.
func TestGenerateEd25519_EncryptedStorageRoundTrip(t *testing.T) {
	_, privPEM, err := sshkeys.GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}

	inner := keys.NewInMemoryKeyStore()
	enc, err := keys.NewEncryptedKeyStorage(inner, testMasterKey)
	if err != nil {
		t.Fatalf("NewEncryptedKeyStorage: %v", err)
	}

	if _, err := enc.PutKey(context.Background(), &keys.PutKeyRequest{
		Record: &keys.KeyRecord{ClientID: "deploy-1", Key: privPEM, Algorithm: "ssh-ed25519"},
	}); err != nil {
		t.Fatalf("PutKey: %v", err)
	}

	innerResp, err := inner.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: "deploy-1"})
	if err != nil {
		t.Fatalf("inner.GetKey: %v", err)
	}
	innerBytes, ok := innerResp.Record.Key.([]byte)
	if !ok {
		t.Fatalf("inner key was %T, want []byte", innerResp.Record.Key)
	}
	if bytes.HasPrefix(innerBytes, []byte("-----BEGIN")) {
		t.Error("inner store holds a PEM block — EncryptedKeyStorage did not encrypt the sshkeys output")
	}

	encResp, err := enc.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: "deploy-1"})
	if err != nil {
		t.Fatalf("enc.GetKey: %v", err)
	}
	gotBytes, _ := encResp.Record.Key.([]byte)
	if !bytes.Equal(gotBytes, privPEM) {
		t.Error("round-trip mismatch: EncryptedKeyStorage altered Ed25519 PEM bytes")
	}
}
