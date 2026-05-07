package apiauth

import (
	"crypto"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/core"
)

// JwtBearerGrantType is the OAuth grant type URI for the
// JWT Bearer authorization grant defined in RFC 7523 §2.1.
//
// A client trades a signed JWT (typically issued by an upstream IdP
// about a subject) for an access token. The assertion's `iss` MUST
// match a trusted issuer in TrustedAssertionIssuers; the JWT signature
// MUST verify against that issuer's public key; standard claims
// (aud/exp/nbf/sub) MUST validate.
//
// Distinct from RFC 7523 §2.2 (JWT for *client* authentication via
// client_assertion + client_assertion_type at the token endpoint),
// which is tracked separately as the `private_key_jwt` /
// `client_secret_jwt` token endpoint auth methods.
//
// See: https://www.rfc-editor.org/rfc/rfc7523#section-2.1
const JwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// TrustedAssertionIssuer describes an upstream IdP whose JWT
// assertions the AS will accept for the jwt-bearer grant
// (RFC 7523 §2.1) and the token-exchange grant with
// subject_token_type=urn:ietf:params:oauth:token-type:jwt
// (RFC 8693 §2.1.1).
//
// At least one of PublicKey or KeyFunc must be set so signatures can
// be verified. KeyFunc takes precedence when both are set; it lets
// callers resolve keys from a JWKS by `kid` header.
//
// The Issuer field is matched verbatim against the JWT's `iss` claim
// (case-sensitive, no trailing-slash normalization — match what the
// upstream IdP actually emits).
type TrustedAssertionIssuer struct {
	// Issuer is the expected `iss` claim value (e.g.,
	// "https://corp-idp.example.com"). REQUIRED.
	Issuer string

	// PublicKey is a static public key for signature verification.
	// Either this or KeyFunc MUST be set. Suitable for tests and
	// single-key issuers; for production with key rotation use KeyFunc.
	PublicKey crypto.PublicKey

	// KeyFunc resolves a public key from the JWT header (typically
	// looking up `kid` against a cached JWKS). When set it takes
	// precedence over PublicKey. The token argument is the parsed
	// (but not yet signature-verified) JWT.
	KeyFunc func(token *jwt.Token) (crypto.PublicKey, error)

	// Audiences lists acceptable `aud` claim values for assertions
	// signed by this issuer. When empty, defaults to the AS's
	// JWTAudience (or its IssuerURL if no audience is configured).
	// RFC 7523 §3 requires the AS to identify itself by the audience
	// claim — the default makes the token endpoint URL implicit.
	Audiences []string

	// AcceptedAlgorithms restricts the JWT alg values accepted for
	// assertions from this issuer (e.g., {"RS256", "ES256"}). Empty
	// = accept any non-`none` algorithm advertised by the JWT library.
	// Set this in production to lock out alg-confusion attacks.
	AcceptedAlgorithms []string
}

// findIssuer returns the TrustedAssertionIssuer matching `iss`, or nil.
func findIssuer(issuers []TrustedAssertionIssuer, iss string) *TrustedAssertionIssuer {
	for i := range issuers {
		if issuers[i].Issuer == iss {
			return &issuers[i]
		}
	}
	return nil
}

// validateAssertion parses + signature-validates a JWT assertion
// against the configured trusted issuers, then validates the
// standard registered claims (aud, exp, nbf). Returns the validated
// claims on success.
//
// Per RFC 7523 §3:
//   - `iss` MUST match a configured trusted issuer.
//   - Signature MUST verify using a key supplied by that issuer.
//   - `aud` MUST contain a value identifying the AS (its token
//     endpoint URL, issuer URL, or configured audience).
//   - `exp` MUST be in the future; `nbf` (if present) in the past.
//   - `sub` is required and identifies the principal the assertion
//     speaks for.
//
// Errors returned here use OAuth 2.0 error codes by convention; callers
// (the grant handlers) translate them to invalid_grant /
// invalid_request HTTP responses.
func validateAssertion(
	a *APIAuth,
	rawAssertion string,
) (jwt.MapClaims, *TrustedAssertionIssuer, error) {
	if rawAssertion == "" {
		return nil, nil, errors.New("assertion required")
	}
	if len(a.TrustedAssertionIssuers) == 0 {
		return nil, nil, errors.New("no trusted assertion issuers configured")
	}

	// First parse without verification so we can pick the issuer.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(rawAssertion, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("malformed assertion: %w", err)
	}
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, errors.New("assertion claims unparseable")
	}
	issStr, _ := claims["iss"].(string)
	if issStr == "" {
		return nil, nil, errors.New("assertion missing iss claim")
	}
	issuer := findIssuer(a.TrustedAssertionIssuers, issStr)
	if issuer == nil {
		return nil, nil, fmt.Errorf("untrusted assertion issuer: %s", issStr)
	}

	// Build the JWT key resolver. KeyFunc wins over PublicKey.
	keyResolver := issuer.KeyFunc
	if keyResolver == nil {
		if issuer.PublicKey == nil {
			return nil, nil, fmt.Errorf("issuer %q has no PublicKey or KeyFunc", issStr)
		}
		pubKey := issuer.PublicKey
		keyResolver = func(*jwt.Token) (crypto.PublicKey, error) {
			return pubKey, nil
		}
	}

	parserOpts := []jwt.ParserOption{}
	if len(issuer.AcceptedAlgorithms) > 0 {
		parserOpts = append(parserOpts, jwt.WithValidMethods(issuer.AcceptedAlgorithms))
	}
	verifyParser := jwt.NewParser(parserOpts...)
	verified, err := verifyParser.Parse(rawAssertion, func(t *jwt.Token) (interface{}, error) {
		return keyResolver(t)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("assertion signature/claims invalid: %w", err)
	}
	if !verified.Valid {
		return nil, nil, errors.New("assertion not valid (signature, exp or nbf)")
	}
	verifiedClaims, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, errors.New("verified claims unparseable")
	}

	// aud validation. Per RFC 7523 §3 the assertion MUST have an aud
	// the AS recognizes. Default to JWTAudience or Issuer URL.
	expectedAudiences := issuer.Audiences
	if len(expectedAudiences) == 0 {
		if a.JWTAudience != "" {
			expectedAudiences = []string{a.JWTAudience}
		} else if a.JWTIssuer != "" {
			expectedAudiences = []string{a.JWTIssuer}
		}
	}
	if len(expectedAudiences) == 0 {
		// Server isn't configured strongly enough to enforce; accept
		// any aud but log loudly so this isn't silent in production.
		log.Printf("apiauth: jwt-bearer/token-exchange — no audience configured for issuer %q; accepting any aud claim. Set TrustedAssertionIssuer.Audiences or APIAuth.JWTAudience for production.", issStr)
	} else {
		matched := false
		for _, aud := range expectedAudiences {
			if matchesAudience(verifiedClaims, aud) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, nil, fmt.Errorf("assertion audience does not match expected: %v", expectedAudiences)
		}
	}

	// sub MUST be present per RFC 7523 §3. Other registered claims
	// (exp, nbf) are validated by jwt.Parse above.
	if sub, _ := verifiedClaims["sub"].(string); sub == "" {
		return nil, nil, errors.New("assertion missing sub claim")
	}

	return verifiedClaims, issuer, nil
}

// handleJwtBearerGrant handles RFC 7523 §2.1 — the client presents a
// signed JWT (in the `assertion` param) issued by a trusted upstream
// IdP and trades it for an access token at our token endpoint.
//
// The assertion's `sub` becomes the access token's subject. Scope is
// taken from the request's `scope` parameter (intersected with what
// the AS would normally grant); RFC 7523 doesn't define how scopes
// are determined — that's deployment-specific.
func (a *APIAuth) handleJwtBearerGrant(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if len(a.TrustedAssertionIssuers) == 0 {
		a.errorResponse(w, "unsupported_grant_type", "jwt-bearer grant not configured", http.StatusBadRequest)
		return
	}
	if req.Assertion == "" {
		a.errorResponse(w, "invalid_request", "assertion parameter required", http.StatusBadRequest)
		return
	}

	claims, _, err := validateAssertion(a, req.Assertion)
	if err != nil {
		a.errorResponse(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}

	subject, _ := claims["sub"].(string) // already validated non-empty
	scopes := core.ParseScopes(req.Scope)

	// Validate authorization_details if present (RFC 9396).
	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		a.errorResponse(w, "invalid_authorization_details", err.Error(), http.StatusBadRequest)
		return
	}

	accessToken, expiresIn, err := a.CreateAccessToken(subject, scopes, req.AuthorizationDetails)
	if err != nil {
		log.Printf("Error creating access token (jwt-bearer grant): %v", err)
		a.errorResponse(w, "server_error", "Failed to create token", http.StatusInternalServerError)
		return
	}

	// No refresh token for jwt-bearer per RFC 7523 — the assertion
	// itself is the renewable credential (re-issued by the upstream
	// IdP and re-presented). Returning a refresh token would muddle
	// session semantics.
	a.tokenResponse(w, accessToken, expiresIn, "", scopes, req.AuthorizationDetails)
}
