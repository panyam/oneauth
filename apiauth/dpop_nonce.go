package apiauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"
)

// DPoPNonceHeader carries a server-issued nonce back to the client
// (RFC 9449 §8). A response carries at most one.
const DPoPNonceHeader = "DPoP-Nonce"

// ErrorUseDPoPNonce is the error code a server returns when it wants the
// client to retry with a nonce in its proof. It is not a failure the client
// should give up on: the accompanying DPoP-Nonce header carries the value to
// use, and the client is expected to mint a new proof and try again.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-8
const ErrorUseDPoPNonce = "use_dpop_nonce"

// defaultNonceLifetime bounds how long an issued nonce stays acceptable.
// RFC 9449 §8 leaves the value to the server. A few minutes is long enough
// that a client is not re-challenged mid-conversation, and short enough that
// the pre-generation window a nonce exists to close stays small.
const defaultNonceLifetime = 5 * time.Minute

// NonceSource issues the nonces a server asks clients to include in their
// DPoP proofs, and decides whether one it is shown is still acceptable.
//
// The point of a nonce is freshness that the client cannot control. An `iat`
// window bounds how old a proof may be, but nothing stops a client, or
// whoever has compromised it, from minting a stack of proofs dated into the
// future and banking them. A proof cannot be built before the server has
// issued the nonce it must contain, which is the property §11.2 is after.
//
// Implementations must be safe for concurrent use.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-8
// See: https://www.rfc-editor.org/rfc/rfc9449#section-11.2
type NonceSource interface {
	// Issue returns a fresh nonce to hand to a client.
	Issue() (string, error)

	// Valid reports whether a nonce the client presented is one this
	// server issued and has not expired. It does not consume the nonce:
	// RFC 9449 expects a client to hold one nonce and use it across
	// requests until challenged again, and single-use replay defense is
	// the `jti` check's job.
	Valid(nonce string) bool
}

// NonceConfig configures NewNonceSource.
type NonceConfig struct {
	// Secret keys the HMAC that makes a nonce unforgeable. Empty
	// generates one per process, which is right for a single node and
	// wrong for a fleet: a nonce issued by one node would be rejected by
	// its neighbour, and the client would loop between challenges.
	// Supply a shared secret when more than one process serves the same
	// endpoint.
	Secret []byte

	// Lifetime is how long an issued nonce stays acceptable. Zero uses
	// defaultNonceLifetime.
	Lifetime time.Duration

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// hmacNonceSource issues nonces that carry their own issue time and a MAC
// over it, so validation is a recomputation rather than a lookup.
//
// The alternative is a stored set of recently issued values, which is what
// RFC 9449 §8 describes ("servers need to keep a window of recent nonces").
// Both give the same guarantee. This one additionally works across a fleet
// without shared storage, needing only a shared secret, and cannot grow
// without bound under load. What it gives up is the ability to revoke a
// single outstanding nonce, which nothing in the protocol asks for.
type hmacNonceSource struct {
	secret   []byte
	lifetime time.Duration
	now      func() time.Time
}

// NewNonceSource returns a NonceSource that needs no storage.
//
// Wire the result into DPoPConfig.NonceSource, and pair it with
// DPoPConfig.NoncePolicy, which decides which requests are challenged.
// Supplying a source alone changes nothing: without a policy the server
// accepts proofs with or without a nonce, which is what keeps this additive
// for clients that have never seen one.
func NewNonceSource(cfg NonceConfig) NonceSource {
	s := &hmacNonceSource{secret: cfg.Secret, lifetime: cfg.Lifetime, now: cfg.Now}
	if len(s.secret) == 0 {
		s.secret = make([]byte, 32)
		if _, err := rand.Read(s.secret); err != nil {
			// A process that cannot read randomness cannot mint
			// anything trustworthy; failing here beats issuing
			// predictable nonces.
			panic(fmt.Sprintf("apiauth: could not seed the DPoP nonce secret: %v", err))
		}
	}
	if s.lifetime <= 0 {
		s.lifetime = defaultNonceLifetime
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// A nonce is timestamp + salt + MAC over both.
//
// The salt is what makes two nonces issued in the same second differ. It is
// not what makes them unforgeable, which is the MAC's job, but a server
// handing the same string to every client for a whole second is a needless
// gift to anyone correlating traffic.
const (
	nonceTimeBytes = 8
	nonceSaltBytes = 8
	nonceMACBytes  = 16
	noncePayload   = nonceTimeBytes + nonceSaltBytes
)

func (s *hmacNonceSource) Issue() (string, error) {
	payload := make([]byte, noncePayload)
	binary.BigEndian.PutUint64(payload[:nonceTimeBytes], uint64(s.now().Unix()))
	if _, err := rand.Read(payload[nonceTimeBytes:]); err != nil {
		return "", fmt.Errorf("read randomness for a DPoP nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(append(payload, s.mac(payload)...)), nil
}

func (s *hmacNonceSource) Valid(nonce string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != noncePayload+nonceMACBytes {
		return false
	}
	payload, mac := raw[:noncePayload], raw[noncePayload:]
	if !hmac.Equal(mac, s.mac(payload)) {
		return false
	}
	age := s.now().Sub(time.Unix(int64(binary.BigEndian.Uint64(payload[:nonceTimeBytes])), 0))
	// A nonce dated in the future is not merely early: our own clock
	// issued it, so a future timestamp means a forged or replayed value.
	return age >= 0 && age <= s.lifetime
}

func (s *hmacNonceSource) mac(payload []byte) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write(payload)
	return m.Sum(nil)[:nonceMACBytes]
}

// NonceRequiredError reports that a request must carry a DPoP nonce and
// carries the nonce to use next.
//
// It is returned instead of a plain proof failure because the two mean
// different things to a client: a bad proof is a bug to fix, while this is
// a handshake step to complete. Handlers translate it into the status and
// headers their endpoint owes (400 at the token endpoint per §8, 401 at a
// resource per §9), both with the DPoP-Nonce header.
type NonceRequiredError struct {
	// Nonce is the fresh value the client should include next.
	Nonce string

	// Description explains which condition triggered the challenge:
	// no nonce supplied, or one that is unknown or expired.
	Description string
}

func (e *NonceRequiredError) Error() string {
	if e.Description != "" {
		return e.Description
	}
	return "a DPoP nonce is required"
}

// writeNonceHeader attaches a freshly issued nonce to a response. A failure
// to issue is swallowed on purpose: the caller is already writing an error
// response, and a challenge without a nonce still tells the client what went
// wrong, it just cannot be retried immediately.
func writeNonceHeader(w http.ResponseWriter, err *NonceRequiredError) {
	if err != nil && err.Nonce != "" {
		w.Header().Set(DPoPNonceHeader, err.Nonce)
	}
}
