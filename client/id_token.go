package client

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// ErrInvalidIDToken is wrapped by every VerifyIDToken failure, and by
// LoginWithBrowser when BrowserLoginRequest.VerifyIDToken is set and the
// token response carries no ID token or one that fails. Match it with
// errors.Is; the message names the check that failed.
var ErrInvalidIDToken = errors.New("invalid id_token")

// DefaultIDTokenClockSkew is how far VerifyIDToken lets `exp` and `iat`
// drift from the local clock when VerifyIDTokenRequest.ClockSkew is zero.
const DefaultIDTokenClockSkew = 30 * time.Second

// idTokenAlgs are the signature algorithms VerifyIDToken accepts. HMAC is
// left out on purpose: an HS256 ID token is signed with a secret the
// client shares (OIDC Core §10.1), so it can't prove the AS issued it, and
// accepting HS256 against an RSA public key is the classic alg-confusion
// forgery. `none` is never accepted.
var idTokenAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// VerifyIDTokenRequest is what VerifyIDToken checks an ID token against.
type VerifyIDTokenRequest struct {
	// IDToken is the compact JWT from the token response. Required.
	IDToken string

	// Issuer is the AS's issuer identifier, compared with `iss` exactly.
	// Required. Take it from discovery (ASMetadata.Issuer), not from the
	// token.
	Issuer string

	// ClientID must appear in `aud`. Required. When `aud` names more than
	// one party, `azp` must be present and equal it.
	ClientID string

	// Keys looks up the signing key by the token's `kid`. Required.
	// Usually keys.NewJWKSKeyStore(meta.JWKSURI). A token without a `kid`
	// is refused.
	Keys keys.KeyLookup

	// Nonce is the value sent on the authorization request. When
	// non-empty the token's `nonce` must equal it; when empty `nonce` is
	// not checked.
	Nonce string

	// AccessToken is the access token from the same response. When
	// non-empty and the token carries `at_hash`, the hash must match it.
	// The code flow makes `at_hash` optional, so its absence passes.
	AccessToken string

	// ClockSkew is the leeway on `exp` and `iat`. Zero means
	// DefaultIDTokenClockSkew.
	ClockSkew time.Duration
}

// IDTokenClaims is a verified ID token. The common claims are typed; the
// rest are in Claims, exactly as the token carried them.
type IDTokenClaims struct {
	Issuer          string
	Subject         string
	Audience        []string
	AuthorizedParty string
	Nonce           string
	ExpiresAt       time.Time
	IssuedAt        time.Time
	// AuthTime is zero when the token has no `auth_time`.
	AuthTime time.Time

	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string

	// Claims holds every claim in the token, the typed ones included.
	Claims map[string]any
}

// VerifyIDToken checks an ID token the way OIDC Core §3.1.3.7 asks a
// client to before trusting it. It checks the signature against Keys with
// an asymmetric algorithm, then `iss`, `aud` (and `azp`), `exp`, `iat`,
// `nonce` and `at_hash`. A token carrying a token-kind marker other than an
// ID token's (Keycloak's `typ` claim of "Bearer", oneauth's `type` claim
// on access tokens) is refused too, so an access token whose audience
// happens to include the client can't pass as an ID token.
//
// Every failure wraps ErrInvalidIDToken.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
func VerifyIDToken(ctx context.Context, req *VerifyIDTokenRequest) (*IDTokenClaims, error) {
	if req == nil || req.IDToken == "" {
		return nil, fmt.Errorf("%w: no token", ErrInvalidIDToken)
	}
	if req.Issuer == "" || req.ClientID == "" || req.Keys == nil {
		return nil, fmt.Errorf("%w: Issuer, ClientID and Keys are required", ErrInvalidIDToken)
	}
	skew := req.ClockSkew
	if skew == 0 {
		skew = DefaultIDTokenClockSkew
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(req.IDToken, claims, func(t *jwt.Token) (any, error) {
		return idTokenKey(ctx, req.Keys, t)
	},
		jwt.WithValidMethods(idTokenAlgs),
		jwt.WithIssuer(req.Issuer),
		jwt.WithAudience(req.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(skew),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIDToken, err)
	}

	if _, ok := claims["iat"]; !ok {
		return nil, fmt.Errorf("%w: no iat", ErrInvalidIDToken)
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return nil, fmt.Errorf("%w: no sub", ErrInvalidIDToken)
	}
	if typ, ok := claims["typ"].(string); ok && typ != "ID" {
		return nil, fmt.Errorf("%w: typ claim %q marks another kind of token", ErrInvalidIDToken, typ)
	}
	if kind, ok := claims["type"].(string); ok {
		return nil, fmt.Errorf("%w: type claim %q marks another kind of token", ErrInvalidIDToken, kind)
	}

	aud, _ := claims.GetAudience()
	azp, _ := claims["azp"].(string)
	if len(aud) > 1 && azp == "" {
		return nil, fmt.Errorf("%w: several audiences and no azp", ErrInvalidIDToken)
	}
	if azp != "" && azp != req.ClientID {
		return nil, fmt.Errorf("%w: azp %q is not this client", ErrInvalidIDToken, azp)
	}

	nonce, _ := claims["nonce"].(string)
	if req.Nonce != "" && nonce != req.Nonce {
		return nil, fmt.Errorf("%w: nonce does not match the one sent", ErrInvalidIDToken)
	}

	if atHash, ok := claims["at_hash"].(string); ok && req.AccessToken != "" {
		want, err := idTokenHash(tok.Method.Alg(), req.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidIDToken, err)
		}
		if atHash != want {
			return nil, fmt.Errorf("%w: at_hash does not match the access token", ErrInvalidIDToken)
		}
	}

	out := &IDTokenClaims{
		AuthorizedParty: azp,
		Nonce:           nonce,
		Audience:        aud,
		Claims:          claims,
	}
	out.Issuer, _ = claims.GetIssuer()
	out.Subject, _ = claims.GetSubject()
	if exp, _ := claims.GetExpirationTime(); exp != nil {
		out.ExpiresAt = exp.Time
	}
	if iat, _ := claims.GetIssuedAt(); iat != nil {
		out.IssuedAt = iat.Time
	}
	if at, ok := claims["auth_time"].(float64); ok {
		out.AuthTime = time.Unix(int64(at), 0)
	}
	out.Email, _ = claims["email"].(string)
	out.EmailVerified, _ = claims["email_verified"].(bool)
	out.Name, _ = claims["name"].(string)
	out.PreferredUsername, _ = claims["preferred_username"].(string)
	return out, nil
}

// idTokenKey finds the verification key for t by `kid`. A key published
// for another algorithm is refused, so an encryption key that shares the
// JWKS (Keycloak publishes an RSA-OAEP one) can't verify a signature.
func idTokenKey(ctx context.Context, lookup keys.KeyLookup, t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("no kid in the header")
	}
	resp, err := lookup.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: kid})
	if err != nil {
		return nil, fmt.Errorf("kid %q: %w", kid, err)
	}
	rec := resp.Record
	if rec.Algorithm != "" && rec.Algorithm != t.Method.Alg() {
		return nil, fmt.Errorf("kid %q is a %s key, token is %s", kid, rec.Algorithm, t.Method.Alg())
	}
	// A PEM-stored key arrives as bytes, a JWKS key as a crypto public
	// key. An HMAC secret is bytes too, and fails to parse here.
	if pem, ok := rec.Key.([]byte); ok {
		return utils.ParsePublicKeyPEM(pem)
	}
	return rec.Key, nil
}

// idTokenHash computes `at_hash` (OIDC Core §3.1.3.6): the left half of
// the hash of the access token, using the hash of the ID token's own
// algorithm, base64url-encoded. EdDSA hashes with SHA-512, as Ed25519
// does.
func idTokenHash(alg, token string) (string, error) {
	var h hash.Hash
	switch {
	case alg == "EdDSA" || strings.HasSuffix(alg, "512"):
		h = sha512.New()
	case strings.HasSuffix(alg, "384"):
		h = sha512.New384()
	case strings.HasSuffix(alg, "256"):
		h = sha256.New()
	default:
		return "", fmt.Errorf("no at_hash for alg %q", alg)
	}
	h.Write([]byte(token))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}
