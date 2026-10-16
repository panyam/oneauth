package utils

// The kid of an RSA key is its RFC 7638 thumbprint. Pinned to the RFC's own
// worked example, so a change to the canonical JSON (member order, padding,
// hash) can't pass unnoticed.
//
// See: https://www.rfc-editor.org/rfc/rfc7638#section-3.1

import "testing"

func TestComputeKid_RFC7638Example(t *testing.T) {
	jwk := JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
		Alg: "RS256",
	}
	pub, _, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := ComputeKid(pub, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; kid != want {
		t.Fatalf("kid %q, want the RFC 7638 §3.1 thumbprint %q", kid, want)
	}
}
