package apiauth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/utils"
)

// JARM response modes (JWT Secured Authorization Response Mode §2.3). Each
// asks for the authorization response as one `response` parameter, a JWT
// signed by the AS, delivered the way its base mode delivers parameters.
// ResponseModeJWT is the default for the response type: query.jwt for
// code, fragment.jwt for the implicit types.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.3
const (
	ResponseModeJWT         = "jwt"
	ResponseModeQueryJWT    = "query.jwt"
	ResponseModeFragmentJWT = "fragment.jwt"
	ResponseModeFormPostJWT = "form_post.jwt"
)

// jarmModes are the JARM modes in the order metadata lists them.
var jarmModes = []string{ResponseModeJWT, ResponseModeQueryJWT, ResponseModeFragmentJWT, ResponseModeFormPostJWT}

// DefaultAuthorizationResponseExpiry is the `exp` of a signed
// authorization response when JARMConfig.Expiry is zero. The client reads
// the response once, right after the redirect, so it only has to outlive
// the browser's trip back. JARM §2.1 asks for a short lifetime and
// suggests 10 minutes as the most.
const DefaultAuthorizationResponseExpiry = 60 * time.Second

// JARMConfig turns on signed authorization responses (OneAuthConfig.JARM).
type JARMConfig struct {
	// Expiry is the `exp` of each response, from when it is signed. Zero
	// uses DefaultAuthorizationResponseExpiry.
	Expiry time.Duration

	// Signer, when set, signs the responses in place of a signer
	// NewOneAuth builds over SigningKey. Use it for a key held elsewhere.
	Signer AuthorizationResponseSigner
}

// AuthorizationResponseSigner signs authorization responses for clients
// that ask for a JARM response mode. AuthorizationHandler.ResponseSigner
// holds one, and its algorithms go in AS metadata's
// `authorization_signing_alg_values_supported`.
type AuthorizationResponseSigner interface {
	// SignAuthorizationResponse returns the response parameters as a
	// signed JWT with `iss`, `aud` (the client) and `exp` (JARM §2.1). A
	// failure means the response can't be sent: AuthorizeVerificationHandler
	// shows an error page and never falls back to an unsigned response.
	SignAuthorizationResponse(ctx context.Context, req *SignAuthorizationResponseRequest) (*SignAuthorizationResponseResponse, error)

	// AuthorizationSigningAlgs lists the algorithms the signer signs with.
	AuthorizationSigningAlgs() []string
}

// SignAuthorizationResponseRequest is the input to
// AuthorizationResponseSigner.SignAuthorizationResponse.
type SignAuthorizationResponseRequest struct {
	// ClientID is the client the response goes to, its `aud`. Required.
	ClientID string

	// Alg is the algorithm to sign with: the client's registered
	// authorization_signed_response_alg. Empty uses the signer's default.
	// One the signer can't sign with is an error, never a fallback to
	// another algorithm or an unsigned response.
	Alg string

	// Params are the response parameters: code or tokens, or error and
	// error_description, with state. Each becomes a string claim. An `iss`
	// among them is replaced by the signer's issuer.
	Params url.Values
}

// SignAuthorizationResponseResponse carries the signed response JWT, the
// value of the `response` parameter.
type SignAuthorizationResponseResponse struct {
	Response string
}

// JWTAuthorizationResponseSignerConfig configures
// NewJWTAuthorizationResponseSigner.
type JWTAuthorizationResponseSignerConfig struct {
	// SigningKey is the AS private key, RSA or EC. Required, and checked
	// at construction even when SigningKeySource is set.
	SigningKey any

	// SigningAlg is the key's JWS algorithm, RS256, PS256 or ES256.
	SigningAlg string

	// SigningKeySource, when set, supplies the key on every response in
	// place of SigningKey, so signing follows a rotation.
	SigningKeySource SigningKeySource

	// Issuer is the `iss` of every response, the AS issuer identifier.
	// Required, since a client checks it against the issuer it discovered.
	Issuer string

	// Expiry is the `exp` of each response. Zero uses
	// DefaultAuthorizationResponseExpiry.
	Expiry time.Duration
}

// jwtAuthorizationResponseSigner implements AuthorizationResponseSigner
// with the AS signing key.
type jwtAuthorizationResponseSigner struct {
	signingKey any
	method     jwt.SigningMethod
	keySource  SigningKeySource
	issuer     string
	expiry     time.Duration
}

// NewJWTAuthorizationResponseSigner returns an AuthorizationResponseSigner
// that signs with the AS key, so clients verify responses against the
// JWKS. It refuses an HMAC key, which a client can't verify, and an empty
// issuer.
func NewJWTAuthorizationResponseSigner(cfg JWTAuthorizationResponseSignerConfig) (AuthorizationResponseSigner, error) {
	if _, ok := cfg.SigningKey.([]byte); ok || cfg.SigningKey == nil {
		return nil, fmt.Errorf("jarm: signed authorization responses need an asymmetric signing key, since a client verifies them against the JWKS")
	}
	method, err := utils.SigningMethodForAlg(cfg.SigningAlg)
	if err != nil {
		return nil, fmt.Errorf("jarm: %w", err)
	}
	if strings.HasPrefix(method.Alg(), "HS") {
		return nil, fmt.Errorf("jarm: signed authorization responses need an asymmetric algorithm, not %s", method.Alg())
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("jarm: an issuer is required, since it is every response's iss")
	}
	expiry := cfg.Expiry
	if expiry <= 0 {
		expiry = DefaultAuthorizationResponseExpiry
	}
	return &jwtAuthorizationResponseSigner{
		signingKey: cfg.SigningKey,
		method:     method,
		keySource:  cfg.SigningKeySource,
		issuer:     cfg.Issuer,
		expiry:     expiry,
	}, nil
}

// AuthorizationSigningAlgs implements AuthorizationResponseSigner.
func (s *jwtAuthorizationResponseSigner) AuthorizationSigningAlgs() []string {
	return []string{s.method.Alg()}
}

// SignAuthorizationResponse implements AuthorizationResponseSigner. Each
// parameter becomes a string claim, and `iss`, `aud` and `exp` overwrite
// any parameter of the same name.
func (s *jwtAuthorizationResponseSigner) SignAuthorizationResponse(ctx context.Context, req *SignAuthorizationResponseRequest) (*SignAuthorizationResponseResponse, error) {
	if req == nil || req.ClientID == "" {
		return nil, fmt.Errorf("jarm: client_id is required (it is the response's aud)")
	}
	if req.Alg != "" && req.Alg != s.method.Alg() {
		return nil, fmt.Errorf("jarm: authorization responses are signed with %s, not %q", s.method.Alg(), req.Alg)
	}
	claims := jwt.MapClaims{}
	for name := range req.Params {
		claims[name] = req.Params.Get(name)
	}
	claims["iss"] = s.issuer
	claims["aud"] = req.ClientID
	claims["exp"] = time.Now().Add(s.expiry).Unix()

	key := s.signingKey
	if s.keySource != nil {
		key, _ = s.keySource.CurrentSigningKey()
	}
	tok := jwt.NewWithClaims(s.method, claims)
	if kid, err := utils.ComputeKid(key, s.method.Alg()); err == nil {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("jarm: sign authorization response: %w", err)
	}
	return &SignAuthorizationResponseResponse{Response: signed}, nil
}

var _ AuthorizationResponseSigner = (*jwtAuthorizationResponseSigner)(nil)

// splitResponseMode splits a JARM mode into its base mode: query.jwt is
// query, and so on. jwt has no base of its own, so it comes back as "",
// for the response type's default. A plain mode comes back unchanged with
// signed false.
func splitResponseMode(mode string) (base string, signed bool) {
	if mode == ResponseModeJWT {
		return "", true
	}
	if b, ok := strings.CutSuffix(mode, ".jwt"); ok {
		return b, true
	}
	return mode, false
}
