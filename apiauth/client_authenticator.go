package apiauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// ClientAssertionTypeJWTBearer is the OAuth assertion-type URN that
// MUST appear in the `client_assertion_type` form parameter when
// authenticating via private_key_jwt or client_secret_jwt
// (RFC 7521 §4.2). Any other value is rejected.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// MaxClientAssertionLifetime caps how far in the future a client
// assertion's `exp` may be from `iat`. RFC 7523 §3 item 4 leaves the
// upper bound to the AS; OIDC Core §9 hints "short-lived". 5 minutes
// is the conventional ceiling matching most major IdPs and bounds the
// JTIStore memory footprint.
const MaxClientAssertionLifetime = 5 * time.Minute

var errInvalidClient = &clientError{"invalid_client"}

type clientError struct{ msg string }

func (e *clientError) Error() string { return e.msg }

// clientAuthenticator implements ClientAuthenticator. The secret path
// uses constant-time comparison; the assertion path verifies a JWT
// signed by the client's registered key (RFC 7523 §2.2 / OIDC Core §9).
type clientAuthenticator struct {
	keyLookup keys.KeyLookup
	jtiStore  JTIStore
}

// NewClientAuthenticator creates a ClientAuthenticator backed by a
// KeyLookup, with an in-memory JTIStore for assertion replay protection.
// For multi-node deployments use NewClientAuthenticatorWithJTIStore to
// wire a distributed JTI store.
func NewClientAuthenticator(kl keys.KeyLookup) ClientAuthenticator {
	return &clientAuthenticator{keyLookup: kl, jtiStore: NewInMemoryJTIStore()}
}

// NewClientAuthenticatorWithJTIStore is like NewClientAuthenticator but
// lets callers supply a custom JTIStore (Redis-backed, etc.).
func NewClientAuthenticatorWithJTIStore(kl keys.KeyLookup, jti JTIStore) ClientAuthenticator {
	if jti == nil {
		jti = NewInMemoryJTIStore()
	}
	return &clientAuthenticator{keyLookup: kl, jtiStore: jti}
}

// AuthenticateClient verifies the supplied client credentials. When
// req.ClientAssertion is set the assertion path runs; otherwise the
// secret path runs. The response's ClientID echoes the authenticated
// client (extracted from the assertion `iss` for private_key_jwt,
// equal to the request ClientID for client_secret_*).
func (a *clientAuthenticator) AuthenticateClient(ctx context.Context, req *AuthenticateClientRequest) (*AuthenticateClientResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("AuthenticateClientRequest is required")
	}
	if a.keyLookup == nil {
		return nil, errInvalidClient
	}
	if req.ClientAssertion != "" {
		return a.authenticateAssertion(req)
	}
	return a.authenticateSecret(req)
}

func (a *clientAuthenticator) authenticateSecret(req *AuthenticateClientRequest) (*AuthenticateClientResponse, error) {
	rec, err := a.keyLookup.GetKey(req.ClientID)
	if err != nil || rec == nil {
		return nil, errInvalidClient
	}
	storedKey, ok := rec.Key.([]byte)
	if !ok {
		return nil, errInvalidClient
	}
	if !constantTimeEqual(string(storedKey), req.ClientSecret) {
		return nil, errInvalidClient
	}
	return &AuthenticateClientResponse{ClientID: req.ClientID, Method: "client_secret"}, nil
}

// authenticateAssertion validates a private_key_jwt client assertion
// per RFC 7523 §3 + OIDC Core §9:
//
//   - client_assertion_type MUST be the registered URN.
//   - The JWT MUST be signed with an alg matching the client's
//     registered alg (no alg-confusion).
//   - iss == sub == client_id.
//   - aud MUST match the configured audience (token endpoint URL or
//     AS issuer URL — the caller decides which).
//   - exp MUST be in the future; iat (if present) in the past; the
//     assertion lifetime (exp - iat) MUST NOT exceed
//     MaxClientAssertionLifetime.
//   - jti MUST NOT have been seen within the assertion lifetime.
func (a *clientAuthenticator) authenticateAssertion(req *AuthenticateClientRequest) (*AuthenticateClientResponse, error) {
	if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
		return nil, fmt.Errorf("%w: client_assertion_type must be %s", errInvalidClient, ClientAssertionTypeJWTBearer)
	}
	if len(req.Audiences) == 0 {
		// Misconfiguration on the handler side, not a client problem.
		// Surface loudly rather than silently accept any aud.
		return nil, errors.New("client assertion validation requires Audiences to be set on the request")
	}

	// First parse without verification so we can pull `iss` and look
	// up the key + algorithm. RFC 7521 §4.1 requires iss == sub ==
	// client_id.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(req.ClientAssertion, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: malformed client_assertion: %v", errInvalidClient, err)
	}
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: assertion claims unparseable", errInvalidClient)
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" {
		return nil, fmt.Errorf("%w: assertion missing iss or sub", errInvalidClient)
	}
	if iss != sub {
		return nil, fmt.Errorf("%w: assertion iss must equal sub", errInvalidClient)
	}
	clientID := iss
	// If the caller supplied a ClientID (from form `client_id` param),
	// it MUST agree with the assertion. RFC 7521 §4.1 — the assertion
	// names the client; a contradicting form param is a forgery
	// attempt or a confused caller.
	if req.ClientID != "" && req.ClientID != clientID {
		return nil, fmt.Errorf("%w: client_id form param does not match assertion iss/sub", errInvalidClient)
	}

	rec, err := a.keyLookup.GetKey(clientID)
	if err != nil || rec == nil {
		return nil, errInvalidClient
	}
	if !utils.IsAsymmetricAlg(rec.Algorithm) {
		// Symmetric-keyed clients cannot use private_key_jwt.
		// client_secret_jwt is a separate ticket (#159).
		return nil, fmt.Errorf("%w: client %q is not registered for private_key_jwt", errInvalidClient, clientID)
	}

	verifyKey, err := utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot decode client key: %v", errInvalidClient, err)
	}

	// Lock the alg to what the client registered. Without this an
	// attacker could swap RS256 for HS256 and use the public key as
	// the HMAC secret (algorithm-confusion, CVE-2016-10555 class).
	verifyParser := jwt.NewParser(jwt.WithValidMethods([]string{rec.Algorithm}))
	verified, err := verifyParser.Parse(req.ClientAssertion, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: assertion signature/claims invalid: %v", errInvalidClient, err)
	}
	if !verified.Valid {
		return nil, fmt.Errorf("%w: assertion not valid (signature, exp, or nbf)", errInvalidClient)
	}
	verifiedClaims, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: verified claims unparseable", errInvalidClient)
	}

	matched := false
	for _, aud := range req.Audiences {
		if matchesAudience(verifiedClaims, aud) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("%w: assertion aud does not match expected audience", errInvalidClient)
	}

	expDate, err := verifiedClaims.GetExpirationTime()
	if err != nil || expDate == nil {
		return nil, fmt.Errorf("%w: assertion missing or invalid exp", errInvalidClient)
	}
	iatDate, err := verifiedClaims.GetIssuedAt()
	if err != nil {
		return nil, fmt.Errorf("%w: assertion has invalid iat", errInvalidClient)
	}
	exp := expDate.Time
	var iat time.Time
	if iatDate != nil {
		iat = iatDate.Time
	} else {
		// Treat absent iat as the earliest moment that still keeps the
		// assertion within the max lifetime — equivalent to assuming
		// the client minted it `MaxClientAssertionLifetime` ago.
		iat = exp.Add(-MaxClientAssertionLifetime)
	}
	now := time.Now()
	lifetime := exp.Sub(iat)
	if lifetime <= 0 {
		return nil, fmt.Errorf("%w: assertion exp must be after iat", errInvalidClient)
	}
	if lifetime > MaxClientAssertionLifetime {
		return nil, fmt.Errorf("%w: assertion lifetime %s exceeds max %s", errInvalidClient, lifetime, MaxClientAssertionLifetime)
	}

	jti, _ := verifiedClaims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("%w: assertion missing jti", errInvalidClient)
	}
	// Replay-protection window must outlive the assertion itself; we
	// track until `exp` plus a small skew buffer.
	replayWindow := exp.Add(30 * time.Second).Sub(now)
	if replayWindow < lifetime {
		replayWindow = lifetime
	}
	if a.jtiStore != nil && a.jtiStore.SeenWithin(jti, replayWindow) {
		return nil, fmt.Errorf("%w: assertion jti has been replayed", errInvalidClient)
	}

	return &AuthenticateClientResponse{ClientID: clientID, Method: "private_key_jwt"}, nil
}
