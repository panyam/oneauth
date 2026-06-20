package core_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
)

// TestPKCE_ChallengeMatchesVerifier pins RFC 7636 §4.2's S256
// transformation: BASE64URL(SHA256(verifier)). Anchors the wire
// behavior any client / AS interop depends on.
func TestPKCE_ChallengeMatchesVerifier(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := core.ComputeCodeChallenge(verifier)

	hash := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	assert.Equal(t, expected, challenge)
}

// TestPKCE_VerifyMatch pins the happy path: a verifier MUST validate
// against the challenge derived from it.
func TestPKCE_VerifyMatch(t *testing.T) {
	verifier := "another-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	challenge := core.ComputeCodeChallenge(verifier)
	assert.True(t, core.VerifyPKCE(core.CodeChallengeMethodS256, challenge, verifier))
}

// TestPKCE_VerifyMismatch pins the failure path: a different verifier
// MUST NOT validate.
func TestPKCE_VerifyMismatch(t *testing.T) {
	verifier := "good-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	challenge := core.ComputeCodeChallenge(verifier)
	assert.False(t, core.VerifyPKCE(core.CodeChallengeMethodS256, challenge, "wrong-verifier"))
}

// TestPKCE_VerifyPlainMatch pins RFC 7636 §4.4: when the stored method
// is plain, the verifier MUST equal the challenge byte-for-byte.
// VerifyPKCE accepts plain unconditionally at the verification layer
// — the OAuth 2.1 §7.5 rejection of plain happens upstream at
// /authorize (gated by AuthorizationHandler.AllowPlainPKCE). This
// split keeps codes minted under an earlier flag setting verifiable
// even if the operator later flips AllowPlainPKCE off; #345.
func TestPKCE_VerifyPlainMatch(t *testing.T) {
	assert.True(t, core.VerifyPKCE(core.CodeChallengeMethodPlain, "match", "match"),
		"plain MUST verify when verifier == challenge")
	assert.False(t, core.VerifyPKCE(core.CodeChallengeMethodPlain, "challenge", "verifier"),
		"plain MUST fail when verifier != challenge")
}

// TestPKCE_VerifyRejectsUnknownMethod pins any unknown method to
// false — defense against a future spec extension being silently
// accepted by an outdated AS.
func TestPKCE_VerifyRejectsUnknownMethod(t *testing.T) {
	verifier := "any-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	challenge := core.ComputeCodeChallenge(verifier)
	assert.False(t, core.VerifyPKCE("S512", challenge, verifier), "unknown method MUST be rejected")
}
