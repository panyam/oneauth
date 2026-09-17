package core

// Confirmation is the RFC 7800 `cnf` claim: the proof-of-possession key a
// token is bound to. A token carrying a Confirmation is sender-constrained —
// presenting it is not enough, the presenter must also prove possession of
// the named key.
//
// One field per binding mechanism, all optional, at most one set in practice:
//
//   - JKT is the RFC 7638 thumbprint of the client's DPoP public key
//     (RFC 9449 §6). The client proves possession by signing a DPoP proof
//     JWT with the matching private key.
//
// mTLS certificate binding (RFC 8705, `x5t#S256`) is the other member of this
// family and lands as a second field when #335 ships — that is why this is a
// struct rather than a bare thumbprint string.
//
// A nil *Confirmation means the token is a plain bearer token: whoever holds
// it can use it.
//
// See: https://www.rfc-editor.org/rfc/rfc7800 (cnf semantics)
// See: https://www.rfc-editor.org/rfc/rfc9449#section-6 (cnf.jkt)
type Confirmation struct {
	JKT string `json:"jkt,omitempty"`
}

// IsEmpty reports whether the confirmation names no key at all. A nil
// receiver is empty, so callers can test a token's binding without a nil
// check of their own. An empty Confirmation must never be emitted as a `cnf`
// claim — an empty `cnf` object claims a binding that nothing enforces.
func (c *Confirmation) IsEmpty() bool {
	return c == nil || c.JKT == ""
}

// Equal reports whether two confirmations name the same key. Nil and empty
// compare equal to each other, so an unbound token matches an unbound
// presentation. Used on the refresh grant to check that the key presented
// with a rotation request is the key the refresh token was issued to.
func (c *Confirmation) Equal(other *Confirmation) bool {
	if c.IsEmpty() || other.IsEmpty() {
		return c.IsEmpty() && other.IsEmpty()
	}
	return c.JKT == other.JKT
}
