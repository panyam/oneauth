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
// client to see. Userinfo serves what it returns for the token's scopes.
// The ID token carries only the claims the authorization request asked
// for by name (OIDC Core §5.4, §5.5), which are looked up by calling it
// with every standard scope. Claims named like a
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

	// PairwiseSalt keys the pairwise subs of clients registered with
	// subject_type pairwise (OIDC Core §8.1, issue 507). It must stay the
	// same for the server's lifetime, or every pairwise client's users get
	// new subs, and it must be at least MinPairwiseSaltLen bytes. Empty
	// means pairwise isn't supported: a pairwise client gets no ID token
	// or userinfo response rather than the user's own ID.
	PairwiseSalt []byte
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

	// Scopes is the granted scope set. It no longer chooses the ID token's
	// claims: an access token is issued beside the ID token, so OIDC Core
	// §5.4 sends scope claims to userinfo. Kept for issuers that need it.
	Scopes []string

	// Nonce is echoed as the `nonce` claim when non-empty (§3.1.3.6).
	Nonce string

	// AuthTime is reported as `auth_time` when non-zero.
	AuthTime time.Time

	// ACR and AMR are reported as `acr` and `amr` (OIDC Core §2) when
	// non-empty: the authentication context class the login met and the
	// methods it used (RFC 8176 values, such as "pwd").
	ACR string
	AMR []string

	// RequestedClaims are claim names the §5.5 `claims` request parameter
	// asked to have in the ID token. Each one the user has is added,
	// whatever Scopes grant.
	RequestedClaims []string

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

	// SigningKeySource, when set, supplies the key on every ID token in
	// place of SigningKey, so it follows a rotation (RotatingSigningKey).
	// SigningKey is still checked at construction.
	SigningKeySource SigningKeySource
	// SubjectForClient maps the user's subject to the `sub` the client
	// sees, which differs for a pairwise client (OneAuth.SubjectForClient).
	// UserClaims still gets the user's own subject. Nil keeps it as is.
	SubjectForClient ClientSubjectFunc
}

// jwtIDTokenIssuer implements IDTokenIssuer with the AS signing key.
type jwtIDTokenIssuer struct {
	signingKey any
	method     jwt.SigningMethod
	issuer     string
	expiry     time.Duration
	userClaims UserClaimsFunc
	keySource  SigningKeySource
	subjectFor ClientSubjectFunc
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
		keySource:  cfg.SigningKeySource,
		subjectFor: cfg.SubjectForClient,
	}, nil
}

// idTokenReservedClaims are the claims CreateIDToken sets itself, which
// UserClaims cannot override.
var idTokenReservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"nonce": true, "auth_time": true, "at_hash": true, "azp": true,
	"acr": true, "amr": true,
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

	// OIDC Core §5.4: an access token is always issued beside this ID
	// token, so scope claims come from userinfo, and the ID token carries
	// only the claims the request asked for by name (§5.5).
	extra, err := collectUserClaims(ctx, i.userClaims, req.Subject, nil, req.RequestedClaims)
	if err != nil {
		return nil, fmt.Errorf("oidc: user claims: %w", err)
	}
	claims := jwt.MapClaims(extra)

	now := time.Now()
	expiresAt := now.Add(i.expiry)
	claims["iss"] = i.issuer
	sub := req.Subject
	if i.subjectFor != nil {
		if sub, err = i.subjectFor(ctx, req.ClientID, req.Subject); err != nil {
			return nil, fmt.Errorf("oidc: subject for client: %w", err)
		}
	}
	claims["sub"] = sub
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
	if req.ACR != "" {
		claims["acr"] = req.ACR
	}
	if len(req.AMR) > 0 {
		claims["amr"] = req.AMR
	}
	if req.AccessToken != "" {
		h, err := tokenHash(i.method.Alg(), req.AccessToken)
		if err != nil {
			return nil, err
		}
		claims["at_hash"] = h
	}

	signingKey := i.key() // once, so the kid and the signature match across a rotation
	tok := jwt.NewWithClaims(i.method, claims)
	if kid, err := utils.ComputeKid(signingKey, i.method.Alg()); err == nil {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(signingKey)
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

// UserinfoSigner signs userinfo responses for clients registered with
// userinfo_signed_response_alg (OIDC Core §5.3.2). The IDTokenIssuer that
// NewJWTIDTokenIssuer returns implements it with the AS signing key, so
// clients verify the response against the JWKS, as they do ID tokens.
// UserinfoHTTPHandler finds it on OneAuth.IDTokenIssuer.
type UserinfoSigner interface {
	// SignUserinfo returns claims as a signed JWT, adding `iss` and an
	// `aud` of the client (§5.3.2). A request for an algorithm not in
	// UserinfoSigningAlgs is an error.
	SignUserinfo(ctx context.Context, req *SignUserinfoRequest) (*SignUserinfoResponse, error)

	// UserinfoSigningAlgs lists the algorithms SignUserinfo signs with,
	// for userinfo_signing_alg_values_supported (OIDC Discovery §3).
	UserinfoSigningAlgs() []string
}

// SignUserinfoRequest is the input to UserinfoSigner.SignUserinfo.
type SignUserinfoRequest struct {
	// ClientID is the client the response goes to, its `aud`. Required.
	ClientID string

	// Alg is the client's registered userinfo_signed_response_alg.
	Alg string

	// Claims is the userinfo response, `sub` included. SignUserinfo
	// doesn't modify it.
	Claims map[string]any
}

// SignUserinfoResponse carries the signed userinfo JWT.
type SignUserinfoResponse struct {
	Token string
}

// UserinfoSigningAlgs implements UserinfoSigner.
func (i *jwtIDTokenIssuer) UserinfoSigningAlgs() []string {
	return []string{i.method.Alg()}
}

// SignUserinfo implements UserinfoSigner. The claims are copied, so the
// caller's map is left alone, and `iss`, `aud` and `iat` overwrite any
// claim of the same name from UserClaims.
func (i *jwtIDTokenIssuer) SignUserinfo(ctx context.Context, req *SignUserinfoRequest) (*SignUserinfoResponse, error) {
	if req == nil || req.ClientID == "" {
		return nil, fmt.Errorf("oidc: client_id is required (it is the userinfo response's aud)")
	}
	if req.Alg != i.method.Alg() {
		return nil, fmt.Errorf("oidc: userinfo is signed with %s, not %q", i.method.Alg(), req.Alg)
	}
	claims := jwt.MapClaims{}
	for k, v := range req.Claims {
		claims[k] = v
	}
	claims["iss"] = i.issuer
	claims["aud"] = req.ClientID
	claims["iat"] = time.Now().Unix()

	signingKey := i.key()
	tok := jwt.NewWithClaims(i.method, claims)
	if kid, err := utils.ComputeKid(signingKey, i.method.Alg()); err == nil {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(signingKey)
	if err != nil {
		return nil, fmt.Errorf("oidc: sign userinfo: %w", err)
	}
	return &SignUserinfoResponse{Token: signed}, nil
}

var _ UserinfoSigner = (*jwtIDTokenIssuer)(nil)

// userinfoClaims builds a userinfo response (OIDC Core §5.3.2): `sub`
// plus the claims the token's scopes grant and the ones its `claims`
// request named.
func userinfoClaims(ctx context.Context, userClaims UserClaimsFunc, subject string, scopes, requested []string) (map[string]any, error) {
	out, err := collectUserClaims(ctx, userClaims, subject, scopes, requested)
	if err != nil {
		return nil, err
	}
	out["sub"] = subject
	return out, nil
}

// standardClaimScopes are the OIDC Core §5.4 scopes, which together grant
// every standard claim.
var standardClaimScopes = []string{"profile", "email", "address", "phone"}

// collectUserClaims returns the claims UserClaims grants for scopes, plus
// each claim in requested that the user has (the §5.5 `claims`
// parameter). A requested claim is looked up by asking UserClaims for
// every standard scope, so a UserClaimsFunc needs no change to serve it.
// Reserved claims never come from UserClaims.
func collectUserClaims(ctx context.Context, userClaims UserClaimsFunc, subject string, scopes, requested []string) (map[string]any, error) {
	out := map[string]any{}
	if userClaims == nil {
		return out, nil
	}
	if len(scopes) > 0 {
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
	if len(requested) == 0 {
		return out, nil
	}
	all, err := userClaims(ctx, subject, standardClaimScopes)
	if err != nil {
		return nil, err
	}
	for _, name := range requested {
		if v, ok := all[name]; ok && !idTokenReservedClaims[name] {
			out[name] = v
		}
	}
	return out, nil
}

// key is the issuer's current signing key: its source's when it has one.
func (i *jwtIDTokenIssuer) key() any {
	if i.keySource != nil {
		k, _ := i.keySource.CurrentSigningKey()
		return k
	}
	return i.signingKey
}
