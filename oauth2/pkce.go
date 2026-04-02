package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// PKCE (Proof Key for Code Exchange, RFC 7636) prevents authorization code
// interception attacks. The client generates a random code_verifier, sends
// a SHA256 hash (code_challenge) with the authorization request, then proves
// knowledge of the original verifier during token exchange.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636

const (
	// PKCECookieName is the cookie name for storing the code verifier.
	PKCECookieName = "pkce_verifier"

	// PKCECookieTTL is how long the verifier cookie lives (covers the OAuth round-trip).
	PKCECookieTTL = 10 * time.Minute

	// CodeVerifierLength is the length of the random verifier in bytes (before base64).
	// 32 bytes → 43 base64url characters, which is the minimum per RFC 7636.
	CodeVerifierLength = 32
)

// GenerateCodeVerifier creates a cryptographically random code verifier
// per RFC 7636 §4.1. Returns a 43-character base64url-encoded string.
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, CodeVerifierLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ComputeCodeChallenge computes the S256 code challenge from a verifier
// per RFC 7636 §4.2: BASE64URL(SHA256(code_verifier)).
func ComputeCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// SetPKCECookie stores the code verifier in an HttpOnly cookie for the
// duration of the OAuth flow. The cookie is read back in the callback
// handler and sent as the code_verifier in the token exchange.
func SetPKCECookie(w http.ResponseWriter, verifier string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     PKCECookieName,
		Value:    verifier,
		Path:     "/",
		MaxAge:   int(PKCECookieTTL.Seconds()),
		HttpOnly: true, // not accessible to JavaScript
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetPKCEVerifier reads the code verifier from the request cookie.
// Returns empty string if the cookie is not present.
func GetPKCEVerifier(r *http.Request) string {
	cookie, err := r.Cookie(PKCECookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// ClearPKCECookie removes the PKCE verifier cookie after use.
func ClearPKCECookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   PKCECookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}
