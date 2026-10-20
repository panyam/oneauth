package apiauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/utils"
)

// OpenID Connect Core 1.0 support: ID tokens from the authorization-code
// grant and the userinfo endpoint. OIDC is opt-in (OneAuthConfig.OIDC);
// without it an `openid` scope is an ordinary scope and no ID token is
// issued.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html

// IDTokenTypeClaim is the value of the `typ` claim on every ID token this
// AS mints. OIDC defines no marker for an ID token, and one signed with
// the AS key and carrying no `type` claim would otherwise validate as an
// access token. Keycloak uses the same claim and value, and
// checkAccessTokenKind already refuses it.
const IDTokenTypeClaim = "ID"

// DefaultIDTokenExpiry is the ID token lifetime when OIDCConfig leaves
// IDTokenExpiry unset. An ID token is read once by the client at login,
// so it does not need to outlive the access token beside it.
const DefaultIDTokenExpiry = 15 * time.Minute

// UserClaimsFunc returns the claims about subject that scopes allow a
// client to see. It backs both the ID token and the userinfo endpoint, so
// the two report the same claims for the same grant. Claims named like a
// registered ID token claim (iss, sub, aud, exp, iat, nonce, auth_time,
// at_hash, azp, typ) are ignored.
//
// Return only what scopes grant. core.FilterClaimsByScope applies the
// OIDC Core §5.4 table to a full profile; localauth.ProfileClaims is a
// ready-made function for local users.
type UserClaimsFunc func(ctx context.Context, subject string, scopes []string) (map[string]any, error)

// OIDCConfig turns on OpenID Connect Core. Set it on
// OneAuthConfig.OIDC.
type OIDCConfig struct {
	// UserClaims supplies the claims about the user beyond `sub`. Nil
	// issues ID tokens and userinfo responses that carry `sub` only.
	UserClaims UserClaimsFunc

	// IDTokenExpiry bounds the ID token lifetime. Zero uses
	// DefaultIDTokenExpiry.
	IDTokenExpiry time.Duration
}

// IDTokenIssuer mints OIDC ID tokens. It follows the gRPC-shape
// convention (175): a single method taking a request struct.
type IDTokenIssuer interface {
	// CreateIDToken mints a signed ID token for the subject, addressed to
	// the client.
	CreateIDToken(ctx context.Context, req *CreateIDTokenRequest) (*CreateIDTokenResponse, error)
}

// CreateIDTokenRequest is the input to IDTokenIssuer.CreateIDToken.
type CreateIDTokenRequest struct {
	// Subject is the user (`sub`). Required.
	Subject string

	// ClientID is the client the ID token is for, its `aud` (OIDC Core
	// §2). Required.
	ClientID string

	// Scopes is the granted scope set, passed to UserClaims to choose the
	// claims.
	Scopes []string

	// Nonce is echoed as the `nonce` claim when non-empty (§3.1.3.6).
	Nonce string

	// AuthTime is reported as `auth_time` when non-zero.
	AuthTime time.Time

	// AccessToken is the access token issued alongside, hashed into
	// `at_hash` (§3.1.3.6) when non-empty, so the client can tell that the
	// two came from the same response.
	AccessToken string
}

// CreateIDTokenResponse wraps the minted ID token.
type CreateIDTokenResponse struct {
	Token     string
	ExpiresAt time.Time
}

// JWTIDTokenIssuerConfig configures NewJWTIDTokenIssuer.
type JWTIDTokenIssuerConfig struct {
	// SigningKey is the AS private key, the same one that signs access
	// tokens and is published in the JWKS. It must be asymmetric: OIDC
	// Core §10.1 signs an HMAC ID token with the client's own secret, not
	// a key the AS shares with resource servers.
	SigningKey any

	// SigningAlg names the JWS algorithm, RS256 or ES256.
	SigningAlg string

	// Issuer is the `iss` claim, the AS issuer identifier.
	Issuer string

	// Expiry bounds the ID token lifetime. Zero uses DefaultIDTokenExpiry.
	Expiry time.Duration

	// UserClaims supplies the claims beyond `sub`. Optional.
	UserClaims UserClaimsFunc
}

// jwtIDTokenIssuer implements IDTokenIssuer with the AS signing key.
type jwtIDTokenIssuer struct {
	signingKey any
	method     jwt.SigningMethod
	issuer     string
	expiry     time.Duration
	userClaims UserClaimsFunc
}

// NewJWTIDTokenIssuer returns an IDTokenIssuer that signs with the AS key.
// It refuses a []byte (HMAC) key and an unknown or symmetric algorithm,
// since an ID token the client cannot verify against the JWKS is of no use
// to it.
func NewJWTIDTokenIssuer(cfg JWTIDTokenIssuerConfig) (IDTokenIssuer, error) {
	if _, ok := cfg.SigningKey.([]byte); ok || cfg.SigningKey == nil {
		return nil, fmt.Errorf("oidc: ID tokens need an asymmetric signing key (OIDC Core §10.1 reserves HMAC for client secrets)")
	}
	method, err := utils.SigningMethodForAlg(cfg.SigningAlg)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	if !atHashSupported(method.Alg()) {
		return nil, fmt.Errorf("oidc: ID tokens are signed with RS256 or ES256, not %q", method.Alg())
	}
	expiry := cfg.Expiry
	if expiry <= 0 {
		expiry = DefaultIDTokenExpiry
	}
	return &jwtIDTokenIssuer{
		signingKey: cfg.SigningKey,
		method:     method,
		issuer:     cfg.Issuer,
		expiry:     expiry,
		userClaims: cfg.UserClaims,
	}, nil
}

// idTokenReservedClaims are the claims CreateIDToken sets itself, which
// UserClaims cannot override.
var idTokenReservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"nonce": true, "auth_time": true, "at_hash": true, "azp": true,
	"typ": true, "type": true, "jti": true,
}

// CreateIDToken implements IDTokenIssuer.
func (i *jwtIDTokenIssuer) CreateIDToken(ctx context.Context, req *CreateIDTokenRequest) (*CreateIDTokenResponse, error) {
	if req == nil || req.Subject == "" {
		return nil, fmt.Errorf("oidc: subject is required")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("oidc: client_id is required (it is the ID token's aud)")
	}

	claims := jwt.MapClaims{}
	if i.userClaims != nil {
		extra, err := i.userClaims(ctx, req.Subject, req.Scopes)
		if err != nil {
			return nil, fmt.Errorf("oidc: user claims: %w", err)
		}
		for k, v := range extra {
			if !idTokenReservedClaims[k] {
				claims[k] = v
			}
		}
	}

	now := time.Now()
	expiresAt := now.Add(i.expiry)
	claims["iss"] = i.issuer
	claims["sub"] = req.Subject
	claims["aud"] = req.ClientID
	claims["iat"] = now.Unix()
	claims["exp"] = expiresAt.Unix()
	claims["typ"] = IDTokenTypeClaim
	if req.Nonce != "" {
		claims["nonce"] = req.Nonce
	}
	if !req.AuthTime.IsZero() {
		claims["auth_time"] = req.AuthTime.Unix()
	}
	if req.AccessToken != "" {
		h, err := tokenHash(i.method.Alg(), req.AccessToken)
		if err != nil {
			return nil, err
		}
		claims["at_hash"] = h
	}

	tok := jwt.NewWithClaims(i.method, claims)
	if kid, err := utils.ComputeKid(i.signingKey, i.method.Alg()); err == nil {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(i.signingKey)
	if err != nil {
		return nil, fmt.Errorf("oidc: sign ID token: %w", err)
	}
	return &CreateIDTokenResponse{Token: signed, ExpiresAt: expiresAt}, nil
}

// tokenHash is OIDC Core §3.1.3.6's at_hash: the left half of the hash of
// the token's ASCII bytes, base64url without padding, using the hash the
// ID token's own alg uses.
func tokenHash(alg, token string) (string, error) {
	if !atHashSupported(alg) {
		return "", fmt.Errorf("oidc: no at_hash for alg %q", alg)
	}
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

// atHashSupported reports whether tokenHash knows the hash for alg. The
// AS signs with RS256 or ES256 (utils.SigningMethodForAlg), both of which
// hash with SHA-256.
func atHashSupported(alg string) bool {
	return alg == "RS256" || alg == "ES256"
}

var _ IDTokenIssuer = (*jwtIDTokenIssuer)(nil)

// userinfoClaims builds a userinfo response (OIDC Core §5.3.2): `sub`
// plus whatever UserClaims returns for the token's scopes.
func userinfoClaims(ctx context.Context, userClaims UserClaimsFunc, subject string, scopes []string) (map[string]any, error) {
	out := map[string]any{}
	if userClaims != nil {
		extra, err := userClaims(ctx, subject, scopes)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			if !idTokenReservedClaims[k] {
				out[k] = v
			}
		}
	}
	out["sub"] = subject
	return out, nil
}
