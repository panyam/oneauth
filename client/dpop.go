package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/utils"
)

// DPoPKey is a client's proof-of-possession key pair (RFC 9449). Tokens the
// authorization server issues against it are bound to it, so a token that
// leaks is unusable by whoever holds it without this key.
//
// One key covers a client's whole session with a server: the same key signs
// the proof on every token request, every refresh, and every resource
// request. Hold it for as long as you hold the tokens it is bound to, and no
// longer — the binding dies with the key, which is the point.
//
// The exception is RFC 9449 §10 `dpop_jkt`, where the spec notes the
// authorization-code binding "only provides similar protections when a
// unique DPoP key is used for each authorization request". A client that
// wants that protection generates a key per authorization rather than per
// session.
//
// A DPoPKey is safe for concurrent use. It holds no per-request state; every
// proof carries a fresh `jti`.
//
// See: https://www.rfc-editor.org/rfc/rfc9449
type DPoPKey struct {
	signer *ecdsa.PrivateKey
	alg    string
	jwk    utils.JWK
	jkt    string
}

// NewDPoPKey generates a fresh ES256 (P-256) key.
//
// ES256 rather than RSA because a client mints a proof on every single
// request: P-256 signing is roughly two orders of magnitude cheaper than
// RSA-2048, and the key is ephemeral so RSA's compatibility advantage buys
// nothing. Use NewDPoPKeyFromECDSA when the key must outlive the process and
// is loaded from storage.
func NewDPoPKey() (*DPoPKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate DPoP key: %w", err)
	}
	return NewDPoPKeyFromECDSA(key)
}

// NewDPoPKeyFromECDSA wraps an existing P-256 private key, for a client that
// persists its key across restarts (an installed application holding tokens
// in a keychain, say). Curves other than P-256 are rejected: the `alg` this
// mints is ES256, and signing an ES256 header with a P-384 key produces a
// proof every server rejects.
func NewDPoPKeyFromECDSA(key *ecdsa.PrivateKey) (*DPoPKey, error) {
	if key == nil {
		return nil, fmt.Errorf("DPoP key is required")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("DPoP key must be P-256 for ES256, got %s", key.Curve.Params().Name)
	}
	jwk := utils.ECDSAPublicKeyToJWK("", "ES256", &key.PublicKey)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	if err != nil {
		return nil, fmt.Errorf("compute DPoP key thumbprint: %w", err)
	}
	return &DPoPKey{signer: key, alg: "ES256", jwk: jwk, jkt: jkt}, nil
}

// Thumbprint returns the RFC 7638 thumbprint of the public key: the value
// the authorization server puts in `cnf.jkt`, and the value to send as the
// `dpop_jkt` authorization request parameter (RFC 9449 §10).
func (k *DPoPKey) Thumbprint() string {
	return k.jkt
}

// Algorithm returns the JWS algorithm this key signs proofs with.
func (k *DPoPKey) Algorithm() string {
	return k.alg
}

// SupportedBy reports whether a server that advertises algs accepts this
// key's algorithm. An empty list means the server published none, which is
// not a refusal, so it passes.
//
// Call it after discovery, using ASMetadata.DPoPSigningAlgValuesSupported.
// Checking up front turns "every request fails with invalid_dpop_proof" into
// one legible error at configuration time.
func (k *DPoPKey) SupportedBy(algs []string) error {
	if len(algs) == 0 {
		return nil
	}
	if !slices.Contains(algs, k.alg) {
		return fmt.Errorf("server does not accept DPoP proofs signed with %s (it accepts %v)", k.alg, algs)
	}
	return nil
}

// Proof mints a DPoP proof JWT for one request (RFC 9449 §4.2).
//
// accessToken binds the proof to the token being presented, via the `ath`
// claim. Pass it for a request to a protected resource, which RFC 9449 §7.1
// requires; leave it empty at the token endpoint, where no access token
// exists yet.
//
// Every call produces a fresh `jti`, so a proof is good for exactly one
// request. Reusing one is a replay and the server rejects it, which matters
// on any retry path: a request retried after a token refresh needs a new
// proof, not the one that was already sent.
func (k *DPoPKey) Proof(method, targetURL, accessToken string) (string, error) {
	htu, err := canonicalHTU(targetURL)
	if err != nil {
		return "", err
	}

	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("generate DPoP jti: %w", err)
	}

	claims := jwt.MapClaims{
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = k.jwkHeader()

	signed, err := token.SignedString(k.signer)
	if err != nil {
		return "", fmt.Errorf("sign DPoP proof: %w", err)
	}
	return signed, nil
}

// jwkHeader renders the public key for the proof's `jwk` header. utils.JWK
// carries no private members by construction, so there is nothing to strip.
func (k *DPoPKey) jwkHeader() map[string]any {
	encoded, err := json.Marshal(k.jwk)
	if err != nil {
		return nil
	}
	var members map[string]any
	if err := json.Unmarshal(encoded, &members); err != nil {
		return nil
	}
	// The server matches on the key itself; kid, use and key_ops add bytes
	// to every request and change nothing about the thumbprint.
	delete(members, "kid")
	delete(members, "use")
	delete(members, "key_ops")
	delete(members, "alg")
	return members
}

// canonicalHTU strips query and fragment, which RFC 9449 §4.3 excludes from
// the `htu` comparison. Sending them would not fail against a conforming
// server, but it leaks request parameters into a token that intermediaries
// can read.
func canonicalHTU(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse request URL for DPoP htu: %w", err)
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), nil
}
