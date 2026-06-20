package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// PKCE code_challenge_method values per RFC 7636 §4.3.
//
//   - S256 — BASE64URL(SHA256(verifier)). RFC 7636 §4.2; OAuth 2.1 §7.5
//     mandates this as the only method for new deployments. Default.
//
//   - plain — challenge == verifier. RFC 7636 §4.4 permits this for
//     environments that can't compute SHA-256. OAuth 2.1 §7.5 retired
//     it; OneAuth's `/authorize` rejects plain unless the AS opts in
//     via OneAuthConfig.AllowPlainPKCE (capability-gating umbrella
//     #344). VerifyPKCE accepts both methods — gating happens at the
//     authorization endpoint, not at code redemption, so that an AS
//     whose flag is later disabled can still verify codes minted while
//     it was on (codes have a short TTL, the window closes quickly).
//
// Lives in core/ (not the oauth2/ sub-module) so apiauth + downstream
// sub-modules can share the helper without taking a dep on the
// browser-side OAuth helper module.
const (
	CodeChallengeMethodS256  = "S256"
	CodeChallengeMethodPlain = "plain"
)

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
// match. Handles both S256 (BASE64URL(SHA256(verifier)) compared
// constant-time to the stored challenge) and plain (verifier ==
// challenge, constant-time). Any other method returns false.
//
// Verification is method-agnostic by design: the OAuth 2.1 §7.5
// rejection of plain happens at the authorization endpoint (gated by
// AuthorizationHandler.AllowPlainPKCE). At redemption time the stored
// method tells the granter which transformation the client applied.
// This keeps codes minted under an earlier flag setting verifiable
// even if the operator later flips AllowPlainPKCE off — codes have a
// short TTL, so any inconsistency window closes quickly.
//
// Constant-time compare on both branches keeps the hot path's timing
// flat. The challenge is not secret, but constant-time removes one
// shape of side-channel concern.
//
// Lives in core/ alongside ComputeCodeChallenge so the PKCE surface is
// centralized in one transport-agnostic home. apiauth's
// authorization-code redemption handler is the primary caller.
func VerifyPKCE(method, challenge, verifier string) bool {
	switch method {
	case CodeChallengeMethodS256:
		computed := ComputeCodeChallenge(verifier)
		return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
	case CodeChallengeMethodPlain:
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	default:
		return false
	}
}
