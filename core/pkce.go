package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// CodeChallengeMethodS256 is the only PKCE transformation OneAuth
// advertises and accepts (RFC 7636 §4.2). OAuth 2.1 deprecated the
// `plain` method; OneAuth rejects it.
//
// Lives in core/ (not the oauth2/ sub-module) so apiauth + downstream
// sub-modules can share the helper without taking a dep on the
// browser-side OAuth helper module.
const CodeChallengeMethodS256 = "S256"

// ComputeCodeChallenge computes the S256 code challenge from a verifier
// per RFC 7636 §4.2: BASE64URL(SHA256(code_verifier)).
//
// Lives here so server-side authorization-code minting (apiauth) and
// any client-side PKCE driver can share the exact same transformation.
func ComputeCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// VerifyPKCE implements RFC 7636 §4.6 verification. Returns true on
// match. Only the S256 method is supported; any other method
// (including "plain") returns false. Uses a constant-time compare to
// keep the hot path's timing flat — the challenge is not secret but
// constant-time removes one shape of side-channel concern.
//
// Lives in core/ alongside ComputeCodeChallenge so the PKCE surface is
// centralized in one transport-agnostic home. apiauth's
// authorization-code redemption handler is the primary caller.
func VerifyPKCE(method, challenge, verifier string) bool {
	if method != CodeChallengeMethodS256 {
		return false
	}
	computed := ComputeCodeChallenge(verifier)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
