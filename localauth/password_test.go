package localauth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/localauth"
)

// TestHashPassword_RoundTrip: a hash checks against its own password and
// no other, and never holds the password itself.
func TestHashPassword_RoundTrip(t *testing.T) {
	hash, err := localauth.HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if strings.Contains(hash, "correct horse") || !strings.HasPrefix(hash, "$2") {
		t.Fatalf("want a bcrypt hash, got %q", hash)
	}
	if !localauth.CheckPassword(hash, "correct horse") {
		t.Error("CheckPassword refused the right password")
	}
	if localauth.CheckPassword(hash, "wrong horse") {
		t.Error("CheckPassword accepted a wrong password")
	}
}

// TestCheckPassword_NoHashTakesABcryptCompare: an empty hash, as for an
// account that doesn't exist, returns false only after a full bcrypt
// comparison. Without it a missing account answers in microseconds and an
// attacker can enumerate accounts by timing.
//
// See: https://cwe.mitre.org/data/definitions/208.html
func TestCheckPassword_NoHashTakesABcryptCompare(t *testing.T) {
	// The same floor as TestCredentialsValidatorWithUsername_TimingOracle.
	const bcryptFloor = 15 * time.Millisecond
	start := time.Now()
	ok := localauth.CheckPassword("", "any-password")
	elapsed := time.Since(start)
	if ok {
		t.Fatal("CheckPassword accepted a password against no hash")
	}
	if elapsed < bcryptFloor {
		t.Fatalf("CheckPassword with no hash took %v, want at least %v (a dummy bcrypt compare)", elapsed, bcryptFloor)
	}
}
