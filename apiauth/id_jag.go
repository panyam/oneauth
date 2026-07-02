package apiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
)

// ID-JAG (Identity Assertion Authorization Grant) support for the MCP
// Enterprise-Managed Authorization flow (SEP-990). An ID-JAG is the
// intermediate credential in the two-stage EMA chain:
//
//	IdP /token   (RFC 8693 token-exchange)   id_token → id-jag
//	AS  /token   (RFC 7523 jwt-bearer)        id-jag   → MCP access token
//
// Stage 1 is "the IdP vouches for the user"; the IdP mints an ID-JAG whose
// `aud` names the resource app's authorization server. Stage 2 is "the AS
// redeems that vouch"; the AS validates the ID-JAG as a trusted-issuer
// assertion and issues an MCP access token bound to the ID-JAG's subject and
// client_id.
//
// See: draft-ietf-oauth-identity-assertion-authz-grant-04
// See: https://github.com/modelcontextprotocol/ext-auth (enterprise-managed-authorization)

// TokenTypeIDJAG is the RFC 8693 token-type URN identifying an ID-JAG. It is
// the value of `requested_token_type` on the stage-1 exchange request and of
// `issued_token_type` on the response. Exported so demos and tests reference
// the constant rather than string-literaling the URN.
const TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"

// IDJAGTypeHeader is the JWS `typ` header value carried by an ID-JAG. The
// stage-2 redeemer asserts this exact value to distinguish an ID-JAG from a
// plain RFC 7523 jwt-bearer assertion before applying ID-JAG-specific
// hardening (single-use jti, client_id binding).
const IDJAGTypeHeader = "oauth-id-jag+jwt"

// TokenTypeNA is the RFC 8693 `token_type` returned for non-access-token
// output. An ID-JAG is not a bearer token — it is redeemed, not presented to
// a resource — so the exchange response reports `token_type: N_A`.
const TokenTypeNA = "N_A"

// IDJAGIssuer mints signed ID-JAG assertions. It follows the gRPC-shape
// convention (175): a single method taking a request struct.
//
// It is a peer interface, wired only when a deployment opts the
// token-exchange grant into ID-JAG issuance (TokenExchangerConfig.IDJAGIssuer
// or OneAuthConfig.IDJAGIssuer). Minting an ID-JAG mints a cross-domain
// authorization grant that a downstream AS will trust, so issuance is off by
// default per the capability-gating convention (#344).
type IDJAGIssuer interface {
	// CreateIDJAG mints a signed `oauth-id-jag+jwt` for the validated
	// subject, bound to the target AS (`aud`) supplied by the caller.
	CreateIDJAG(ctx context.Context, req *CreateIDJAGRequest) (*CreateIDJAGResponse, error)
}

// CreateIDJAGRequest is the input to IDJAGIssuer.CreateIDJAG.
type CreateIDJAGRequest struct {
	// Subject is the user identifier (RFC 7519 `sub`), taken from the
	// validated stage-1 subject_token. Required.
	Subject string

	// Audience is the ID-JAG `aud` claim — the issuer identifier of the
	// resource app's authorization server that will redeem this ID-JAG.
	// Bound from the exchange request `audience` param (RFC 8693 §2.1),
	// which is why the issuer does NOT pin an audience at construction.
	// Required: an ID-JAG with no target AS is not redeemable.
	Audience string

	// ClientID is the MCP client identifier the redeeming AS knows the
	// client by (`client_id` claim). Carried so the stage-2 redeemer can
	// bind the issued access token to the client per the draft §5
	// CIMD/DCR constraint. Optional.
	ClientID string

	// Scopes, when non-empty, is emitted as a space-delimited `scope`
	// claim so the redeeming AS can scope the eventual access token.
	Scopes []string

	// Resource is the RFC 8707 resource indicator (the MCP server URL).
	// Carried as a `resource` claim so the redeeming AS can bind the
	// eventual access token to the right MCP server. Optional.
	Resource string

	// AuthorizationDetails carries RFC 9396 detail objects through the
	// exchange when present. Optional.
	AuthorizationDetails []core.AuthorizationDetail
}

// CreateIDJAGResponse wraps the minted ID-JAG.
type CreateIDJAGResponse struct {
	// Token is the serialized `oauth-id-jag+jwt`. It becomes the
	// `access_token` field of the RFC 8693 exchange response (that is the
	// field RFC 8693 §2.2 uses to carry the issued token regardless of
	// its type).
	Token string

	// ExpiresIn is the ID-JAG lifetime in seconds.
	ExpiresIn int64
}

// IDJAGIssuerConfig configures the default IDJAGIssuer. The signing material
// is the IdP's key — an ID-JAG is signed by the IdP (stage 1), not by the
// resource AS that redeems it (stage 2).
type IDJAGIssuerConfig struct {
	// SigningKey is the IdP signing key. For HS256 pass []byte; for
	// RS256/ES256 pass the private key.
	SigningKey any

	// SigningAlg names the JWS algorithm (e.g. "RS256"). Empty falls back
	// to HS256 when SigningKey is a []byte.
	SigningAlg string

	// Issuer is the IdP issuer URL — the ID-JAG `iss` claim, and the key
	// under which the redeeming AS looks up the IdP JWKS.
	Issuer string

	// TTL bounds the ID-JAG lifetime. An ID-JAG is single-use and redeemed
	// immediately, so this stays short — long enough for two network hops
	// plus clock skew, short enough that a leaked (unredeemed) ID-JAG is
	// useless quickly. Defaults to 2 minutes when unset.
	TTL time.Duration
}

// idjagDefaultTTL is the fallback ID-JAG lifetime, matching the short-lived
// posture of logout_token (single-use, redeemed promptly).
const idjagDefaultTTL = 2 * time.Minute

// jwtIDJAGIssuer implements IDJAGIssuer by signing an `oauth-id-jag+jwt` with
// the IdP key.
type jwtIDJAGIssuer struct {
	signingKey any
	signingAlg string
	issuer     string
	ttl        time.Duration
}

// NewJWTIDJAGIssuer returns an IDJAGIssuer that signs ID-JAGs with the
// supplied IdP key. Wire it into TokenExchangerConfig.IDJAGIssuer (or
// OneAuthConfig.IDJAGIssuer) to opt the token-exchange grant into ID-JAG
// issuance.
func NewJWTIDJAGIssuer(cfg IDJAGIssuerConfig) IDJAGIssuer {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = idjagDefaultTTL
	}
	return &jwtIDJAGIssuer{
		signingKey: cfg.SigningKey,
		signingAlg: cfg.SigningAlg,
		issuer:     cfg.Issuer,
		ttl:        ttl,
	}
}

// CreateIDJAG implements IDJAGIssuer.
//
// The claim set is the draft-04 §5 minimum — `iss`, `sub`, `aud`, `jti`,
// `iat`, `exp` — plus `client_id`, `scope`, `resource`, and
// `authorization_details` when the caller supplies them. The JWS header
// carries `typ=oauth-id-jag+jwt` so the redeemer can distinguish an ID-JAG
// from a plain jwt-bearer assertion before parsing claims.
func (i *jwtIDJAGIssuer) CreateIDJAG(ctx context.Context, req *CreateIDJAGRequest) (*CreateIDJAGResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateIDJAGRequest is required")
	}
	if req.Subject == "" {
		return nil, fmt.Errorf("id-jag: subject is required")
	}
	if req.Audience == "" {
		return nil, fmt.Errorf("id-jag: audience (target AS issuer) is required")
	}

	jti, err := core.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("id-jag: jti: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": i.issuer,
		"sub": req.Subject,
		"aud": req.Audience,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(i.ttl).Unix(),
	}
	if req.ClientID != "" {
		claims["client_id"] = req.ClientID
	}
	if len(req.Scopes) > 0 {
		claims["scope"] = core.JoinScopes(req.Scopes)
	}
	if req.Resource != "" {
		claims["resource"] = req.Resource
	}
	if len(req.AuthorizationDetails) > 0 {
		claims["authorization_details"] = req.AuthorizationDetails
	}

	method, err := utils.SigningMethodForAlg(i.signingAlg)
	if err != nil {
		if _, ok := i.signingKey.([]byte); ok {
			method = jwt.SigningMethodHS256
		} else {
			return nil, fmt.Errorf("id-jag: invalid signing alg: %w", err)
		}
	}

	tok := jwt.NewWithClaims(method, claims)
	tok.Header["typ"] = IDJAGTypeHeader
	if kid, kidErr := utils.ComputeKid(i.signingKey, method.Alg()); kidErr == nil {
		tok.Header["kid"] = kid
	}

	signed, err := tok.SignedString(i.signingKey)
	if err != nil {
		return nil, fmt.Errorf("id-jag: sign: %w", err)
	}
	return &CreateIDJAGResponse{Token: signed, ExpiresIn: int64(i.ttl.Seconds())}, nil
}

// assertionHeaderTyp returns the JWS `typ` header of a compact JWT without
// verifying its signature. The redeemer uses it to branch on ID-JAG vs plain
// jwt-bearer. Reading `typ` unverified is safe: the caller only trusts the
// value after ValidateAssertion verifies the signature over the same header
// bytes. Returns "" when the token is malformed or carries no `typ`.
func assertionHeaderTyp(raw string) string {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	tok, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return ""
	}
	typ, _ := tok.Header["typ"].(string)
	return typ
}

var _ IDJAGIssuer = (*jwtIDJAGIssuer)(nil)
