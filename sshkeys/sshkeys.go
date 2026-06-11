// Package sshkeys generates SSH keypairs for downstream automation
// consumers and packages them in the shapes oneauth/keys.KeyStorage and
// the OpenSSH ecosystem (authorized_keys files, GitHub deploy keys,
// ssh-agent) actually consume.
//
// Currently Ed25519 only. The private side is an OpenSSH-format PEM
// block ("OPENSSH PRIVATE KEY"), which oneauth/keys.EncryptedKeyStorage
// recognizes and encrypts at rest via its content-driven "header type
// contains PRIVATE" predicate — callers can persist the returned PEM
// directly through KeyStorage without leaking plaintext.
//
// Out of scope here: RSA/ECDSA SSH key generation (Ed25519 is the
// modern default), shelling out to ssh-keygen (filesystem side effects
// + missing binary in container/FaaS environments), and Cloud KMS
// integration (tracked under oneauth issue 9).
package sshkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// GenerateEd25519 generates a fresh Ed25519 keypair and returns the
// public side as a single authorized_keys line (e.g.,
// "ssh-ed25519 AAAAC3..." with no trailing comment, terminated by a
// newline as ssh.MarshalAuthorizedKey emits), and the private side as
// an OpenSSH-format PEM block with header "OPENSSH PRIVATE KEY".
//
// Both outputs are deployment-ready: the public line concatenates into
// an authorized_keys file as-is; the private PEM is what callers persist
// via keys.KeyStorage (EncryptedKeyStorage will encrypt it at rest based
// on the PEM header type). Parseable by ssh.ParseAuthorizedKey and
// ssh.ParsePrivateKey respectively.
func GenerateEd25519() (publicAuthorizedKey, privatePEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519 keypair: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh.NewPublicKey: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, nil, fmt.Errorf("ssh.MarshalPrivateKey: %w", err)
	}

	return ssh.MarshalAuthorizedKey(sshPub), pem.EncodeToMemory(block), nil
}
