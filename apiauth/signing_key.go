package apiauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/panyam/oneauth/utils"
)

// SigningKeySource supplies the key the AS signs its tokens with, read on
// every signature, so the key can change while the server runs (issue
// 507). OneAuthConfig.SigningKeySource wires one into every issuer and the
// validator.
type SigningKeySource interface {
	// CurrentSigningKey returns the private key (or HMAC secret) and its
	// JWS algorithm. The algorithm never changes for one source.
	CurrentSigningKey() (key any, alg string)
}

// RotatingSigningKey is a SigningKeySource whose key Rotate replaces. Safe
// for concurrent use: a token is signed with whichever key was current
// when it was minted.
//
// Rotate changes only the signing side. Publishing the new public key, and
// keeping the old one verifiable for a grace period, is the caller's: put
// the new key in the KeyStore under OneAuthConfig.OwnKeyClientID and the
// old one in the KidStore with an expiry, as AppRegistrar.RotateSecret
// does for a client. Tokens signed with the old key verify through that
// KidStore entry until it expires (OIDC Core §10.1.1).
type RotatingSigningKey struct {
	mu  sync.RWMutex
	key any
	alg string
}

// NewRotatingSigningKey returns a source signing with key under alg. It
// refuses a key that can't sign alg: an HMAC secret for HS*, an RSA private
// key for RS*/PS*, an ECDSA private key on alg's curve for ES*.
func NewRotatingSigningKey(key any, alg string) (*RotatingSigningKey, error) {
	if err := keyFitsAlg(key, alg); err != nil {
		return nil, err
	}
	return &RotatingSigningKey{key: key, alg: alg}, nil
}

// CurrentSigningKey implements SigningKeySource.
func (r *RotatingSigningKey) CurrentSigningKey() (any, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.key, r.alg
}

// Rotate makes key the signing key. The algorithm stays the same, so key
// must fit it; a key that doesn't is refused and the current one kept.
func (r *RotatingSigningKey) Rotate(key any) error {
	if err := keyFitsAlg(key, r.alg); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.key = key
	return nil
}

// keyFitsAlg reports whether key is a private key (or secret) that signs
// alg.
func keyFitsAlg(key any, alg string) error {
	switch alg {
	case "HS256", "HS384", "HS512":
		if b, ok := key.([]byte); ok && len(b) > 0 {
			return nil
		}
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		if _, ok := key.(*rsa.PrivateKey); ok {
			return nil
		}
	case "ES256", "ES384", "ES512":
		curve := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg]
		if k, ok := key.(*ecdsa.PrivateKey); ok && k.Curve == curve {
			return nil
		}
	}
	return fmt.Errorf("apiauth: a %T can't sign %s", key, alg)
}

// verifyKeyAndKid returns what verifies tokens key signs, and their kid:
// the public half of a private key, or the secret itself.
func verifyKeyAndKid(key any, alg string) (any, string) {
	verify := key
	if s, ok := key.(crypto.Signer); ok {
		verify = s.Public()
	}
	kid, err := utils.ComputeKid(verify, alg)
	if err != nil {
		return verify, ""
	}
	return verify, kid
}
