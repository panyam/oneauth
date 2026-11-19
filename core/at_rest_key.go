package core

import (
	"crypto/sha256"
	"encoding/hex"
)

// AtRestKey is the key a store files a single-use bearer value under,
// such as an authorization code or a pushed request's request_uri:
// "sha256:" followed by the hex digest. Anyone holding the value can
// redeem it, so storing only the digest means a copy of the store (a
// backup, a log of rows, a read-only replica) can't be replayed. Lookups
// hash the presented value and match the digest.
//
// The values hashed here are 256-bit random strings, so a fast unsalted
// hash is enough: there is nothing to brute-force.
func AtRestKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
