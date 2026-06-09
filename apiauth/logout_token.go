package apiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
)

// BCLEventType is the single event-identifier URI defined by OIDC Back-Channel
// Logout 1.0 §2.4. Every logout_token MUST carry an `events` claim whose only
// key is this URI; the value is the empty JSON object.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
const BCLEventType = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenIssuer mints signed `logout_token` JWTs per OIDC Back-Channel
// Logout 1.0 §2.4 for delivery to a client's registered backchannel_logout_uri.
//
// It follows the gRPC-shape convention adopted in 175 — a single method that
// takes a request struct and returns a wrapped response. Implementations reuse
// the AS signing key already in use by TokenIssuer so RSes can verify
// logout_tokens against the same JWKS they use for access tokens.
type LogoutTokenIssuer interface {
	// CreateLogoutToken mints a signed logout_token. The returned response
	// carries the serialized JWT only; the dispatcher is responsible for
	// transporting it.
	CreateLogoutToken(ctx context.Context, req *CreateLogoutTokenRequest) (*CreateLogoutTokenResponse, error)
}

// CreateLogoutTokenRequest is the input to LogoutTokenIssuer.CreateLogoutToken.
//
// At least one of Subject and SID MUST be populated. Per OIDC BCL §2.4 a
// logout_token without both `sub` and `sid` is invalid and MUST be rejected by
// the receiving client; the constructor enforces this so callers cannot
// silently mint a token that every conforming RS will reject.
type CreateLogoutTokenRequest struct {
	// Audience is the receiving client's client_id. Per §2.4 this becomes the
	// `aud` claim and identifies which client the logout applies to. Required.
	Audience string

	// Subject is the user identifier (RFC 7519 `sub`) whose session ended.
	// Optional iff SID is set; required otherwise.
	Subject string

	// SID is the session identifier (`sid`). When the receiving client
	// registered with backchannel_logout_session_required=true the AS MUST
	// include this; otherwise SHOULD include when known. oneauth maps SID to
	// the refresh-token family ID — the closest analogue to an OIDC session
	// the library tracks today.
	SID string
}

// CreateLogoutTokenResponse wraps the minted logout_token JWT.
type CreateLogoutTokenResponse struct {
	// Token is the serialized JWS. It is ready to POST as the value of the
	// `logout_token` form field per §2.5.
	Token string
}

// jwtLogoutTokenIssuer implements LogoutTokenIssuer by reusing the AS signing
// key — the same private key that signs access tokens. Reusing the key means
// receiving clients verify logout_tokens against the JWKS they already trust
// for access-token validation.
type jwtLogoutTokenIssuer struct {
	signingKey any
	signingAlg string
	issuer     string
	tokenTTL   time.Duration
}

// JWTLogoutTokenIssuerConfig configures a jwtLogoutTokenIssuer.
type JWTLogoutTokenIssuerConfig struct {
	// SigningKey is the AS signing key. For HS256 pass []byte; for RS256/ES256
	// pass the private key.
	SigningKey any

	// SigningAlg names the JWS algorithm (e.g. "RS256"). Empty falls back to
	// HS256 when SigningKey is a []byte.
	SigningAlg string

	// Issuer is the AS issuer URL — the value the receiver expects as the
	// `iss` claim and the key under which it looked up the AS JWKS.
	Issuer string

	// TokenTTL bounds the validity window for replay protection. The OIDC BCL
	// spec does not require `exp` but receivers are encouraged to reject
	// stale tokens; we default to 2 minutes — long enough for slow networks,
	// short enough that a leaked token isn't useful for long.
	TokenTTL time.Duration
}

// NewJWTLogoutTokenIssuer returns a LogoutTokenIssuer that signs logout_tokens
// with the supplied key.
func NewJWTLogoutTokenIssuer(cfg JWTLogoutTokenIssuerConfig) LogoutTokenIssuer {
	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &jwtLogoutTokenIssuer{
		signingKey: cfg.SigningKey,
		signingAlg: cfg.SigningAlg,
		issuer:     cfg.Issuer,
		tokenTTL:   ttl,
	}
}

// CreateLogoutToken implements LogoutTokenIssuer.
//
// The claims set is exactly the §2.4 minimum plus `exp`. We deliberately omit
// any `nonce` claim — the spec forbids it on logout_tokens (§2.4 ¶6) and a
// stray nonce is grounds for the receiver to reject the token. `events` is
// emitted as `{<BCLEventType>: {}}` exactly — receivers test for the presence
// of the URI key, not the value shape.
func (i *jwtLogoutTokenIssuer) CreateLogoutToken(ctx context.Context, req *CreateLogoutTokenRequest) (*CreateLogoutTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateLogoutTokenRequest is required")
	}
	if req.Audience == "" {
		return nil, fmt.Errorf("logout_token: audience (client_id) is required")
	}
	if req.Subject == "" && req.SID == "" {
		return nil, fmt.Errorf("logout_token: at least one of sub and sid MUST be present (OIDC BCL §2.4)")
	}

	jti, err := core.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("logout_token: jti: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": i.issuer,
		"aud": req.Audience,
		"iat": now.Unix(),
		"exp": now.Add(i.tokenTTL).Unix(),
		"jti": jti,
		"events": map[string]any{
			BCLEventType: map[string]any{},
		},
	}
	if req.Subject != "" {
		claims["sub"] = req.Subject
	}
	if req.SID != "" {
		claims["sid"] = req.SID
	}

	method, err := utils.SigningMethodForAlg(i.signingAlg)
	if err != nil {
		if _, ok := i.signingKey.([]byte); ok {
			method = jwt.SigningMethodHS256
		} else {
			return nil, fmt.Errorf("logout_token: invalid signing alg: %w", err)
		}
	}

	tok := jwt.NewWithClaims(method, claims)
	// Per §2.4 the JWS header carries `typ=logout+jwt` so receivers can
	// distinguish logout_tokens from access/id tokens before parsing claims.
	tok.Header["typ"] = "logout+jwt"
	if kid, kidErr := utils.ComputeKid(i.signingKey, method.Alg()); kidErr == nil {
		tok.Header["kid"] = kid
	}

	signed, err := tok.SignedString(i.signingKey)
	if err != nil {
		return nil, fmt.Errorf("logout_token: sign: %w", err)
	}
	return &CreateLogoutTokenResponse{Token: signed}, nil
}
