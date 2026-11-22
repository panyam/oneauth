package fapi2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// ClientKey is the key pair one test client signs its client assertions
// with. The plan's first client has a PS256 key and the second an ES256
// key, so a run covers both of the FAPI 2.0 algorithms oneauth registers.
// The RSA key also lets the harness run
// ensure-signed-client-assertion-with-RS256-fails, which it skips for an EC
// key (issue 558).
type ClientKey struct {
	// Alg is "PS256" or "ES256".
	Alg   string
	KeyID string

	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
}

// NewClientKey generates an ES256 (P-256) key with its RFC 7638
// thumbprint as the kid.
func NewClientKey() (ClientKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ClientKey{}, err
	}
	k := ClientKey{Alg: "ES256", ec: priv}
	k.KeyID = k.thumbprint()
	return k, nil
}

// NewRSAClientKey generates a 2048-bit PS256 key, the minimum size FAPI
// 2.0 §5.4.1 allows, with its RFC 7638 thumbprint as the kid.
func NewRSAClientKey() (ClientKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ClientKey{}, err
	}
	k := ClientKey{Alg: "PS256", rsa: priv}
	k.KeyID = k.thumbprint()
	return k, nil
}

// PublicJWK is the key's public half, as DCR registers it.
func (k ClientKey) PublicJWK() map[string]string {
	if k.rsa != nil {
		return map[string]string{
			"kty": "RSA", "alg": k.Alg, "use": "sig", "kid": k.KeyID,
			"n": b64(k.rsa.N, 0), "e": b64(big.NewInt(int64(k.rsa.E)), 0),
		}
	}
	return map[string]string{
		"kty": "EC", "crv": "P-256", "alg": k.Alg, "use": "sig", "kid": k.KeyID,
		"x": b64(k.ec.X, 32), "y": b64(k.ec.Y, 32),
	}
}

// PrivateJWK adds the private members. The harness signs the client's
// assertions itself, so the plan config carries the private key. An RSA
// key carries its CRT values too (RFC 7518 §6.3.2).
func (k ClientKey) PrivateJWK() map[string]string {
	j := k.PublicJWK()
	if k.rsa != nil {
		k.rsa.Precompute()
		j["d"] = b64(k.rsa.D, 0)
		j["p"] = b64(k.rsa.Primes[0], 0)
		j["q"] = b64(k.rsa.Primes[1], 0)
		j["dp"] = b64(k.rsa.Precomputed.Dp, 0)
		j["dq"] = b64(k.rsa.Precomputed.Dq, 0)
		j["qi"] = b64(k.rsa.Precomputed.Qinv, 0)
		return j
	}
	j["d"] = b64(k.ec.D, 32)
	return j
}

// thumbprint is the RFC 7638 SHA-256 thumbprint of the public key. The
// members are in lexicographic order, as §3.3 requires.
func (k ClientKey) thumbprint() string {
	j := k.PublicJWK()
	var canon []byte
	if k.rsa != nil {
		canon, _ = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{j["e"], "RSA", j["n"]})
	} else {
		canon, _ = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{"P-256", "EC", j["x"], j["y"]})
	}
	sum := sha256.Sum256(canon)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// b64 is the base64url encoding of n. size pads it to a fixed width, as
// EC coordinates need; 0 uses the minimal big-endian bytes, as RSA
// members need.
func b64(n *big.Int, size int) string {
	if size == 0 {
		return base64.RawURLEncoding.EncodeToString(n.Bytes())
	}
	return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, size)))
}
