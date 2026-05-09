package client

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/utils"
)

// AuthMethodPrivateKeyJWT names the RFC 7521 §4.2 / RFC 7523 §2.2 /
// OIDC Core §9 token-endpoint client authentication method where the
// client signs a JWT with its registered private key and sends it as
// `client_assertion`. Strongest of the standard methods — there is no
// shared secret to leak.
const AuthMethodPrivateKeyJWT TokenEndpointAuthMethod = "private_key_jwt"

// ClientAssertionConfig carries the material a client needs to mint a
// `private_key_jwt` assertion. Construct once per AuthClient and reuse;
// each MintClientAssertion call generates a fresh `jti`, `iat`, and
// `exp` so assertions are single-use.
type ClientAssertionConfig struct {
	// PrivateKey is the asymmetric signing key — *rsa.PrivateKey or
	// *ecdsa.PrivateKey. Must match the public key registered with the
	// AS via DCR (RFC 7591) for the same `client_id`.
	PrivateKey crypto.PrivateKey

	// SigningAlg is the JWS alg value: "RS256" or "ES256". Must match
	// the alg the AS registered for this client.
	SigningAlg string

	// KeyID, when non-empty, is set as the `kid` JWS header so the AS
	// can disambiguate among multiple registered keys for the same
	// client. Optional — clients with a single key may leave it blank.
	KeyID string

	// Lifetime is how long the minted assertion is valid for. Defaults
	// to 60s (recommended ceiling for FAPI / most IdPs). Must be ≤
	// 5min to satisfy OneAuth's server-side assertion lifetime cap;
	// other AS implementations are typically stricter.
	Lifetime time.Duration
}

// DefaultClientAssertionLifetime is the assertion lifetime applied when
// ClientAssertionConfig.Lifetime is zero. 60 seconds matches the
// short-lived recommendation in OIDC Core §9.
const DefaultClientAssertionLifetime = 60 * time.Second

// MintClientAssertion produces a signed JWT bearing the client's
// identity, suitable for use as the `client_assertion` form parameter
// at the token / introspection / revocation endpoints.
//
// Claims set per RFC 7523 §3 + OIDC Core §9:
//
//	iss = clientID
//	sub = clientID
//	aud = audience  (token endpoint URL or AS issuer URL)
//	jti = random 128-bit hex string
//	iat = now
//	exp = now + cfg.Lifetime  (or default)
//
// Returns the compact JWS string ready to drop into a form value.
func MintClientAssertion(clientID, audience string, cfg ClientAssertionConfig) (string, error) {
	if clientID == "" {
		return "", fmt.Errorf("MintClientAssertion: clientID is required")
	}
	if audience == "" {
		return "", fmt.Errorf("MintClientAssertion: audience is required")
	}
	if cfg.PrivateKey == nil {
		return "", fmt.Errorf("MintClientAssertion: PrivateKey is required")
	}
	if cfg.SigningAlg == "" {
		return "", fmt.Errorf("MintClientAssertion: SigningAlg is required")
	}

	method, err := utils.SigningMethodForAlg(cfg.SigningAlg)
	if err != nil {
		return "", fmt.Errorf("MintClientAssertion: %w", err)
	}

	lifetime := cfg.Lifetime
	if lifetime <= 0 {
		lifetime = DefaultClientAssertionLifetime
	}

	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("MintClientAssertion: jti: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
	}

	tok := jwt.NewWithClaims(method, claims)
	if cfg.KeyID != "" {
		tok.Header["kid"] = cfg.KeyID
	}

	signed, err := tok.SignedString(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("MintClientAssertion: sign: %w", err)
	}
	return signed, nil
}

// applyAssertionToForm attaches a freshly minted `client_assertion` +
// `client_assertion_type` to the form, plus `client_id` (some IdPs
// require it even though it duplicates the assertion `iss`).
func applyAssertionToForm(clientID, assertion string, data url.Values) {
	data.Set("client_id", clientID)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", assertion)
}

// randomJTI returns a 128-bit random string suitable for the assertion
// `jti` claim. Hex-encoded so it's URL-safe and trivially comparable.
func randomJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Use base64 raw-url to keep the string compact (22 chars) without
	// pad bytes that some servers strip inconsistently.
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
