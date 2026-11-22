package client

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/keys"
)

// VerifyAuthorizationResponseRequest is what VerifyAuthorizationResponse
// checks a signed (JARM) authorization response against.
type VerifyAuthorizationResponseRequest struct {
	// Response is the `response` parameter from the callback: the compact
	// JWT the AS signed. Required.
	Response string

	// Issuer is the AS issuer identifier from discovery. The JWT's `iss`
	// must equal it, which stops a response from one AS being replayed as
	// another's (JARM §4.4, the mix-up attack). Required.
	Issuer string

	// ClientID is this client. The JWT's `aud` must contain it. Required.
	ClientID string

	// Keys finds the AS signing key by the JWT's `kid`. Usually
	// keys.NewJWKSKeyStore(meta.JWKSURI). Required.
	Keys keys.KeyLookup

	// ClockSkew is the leeway on `exp`. Zero uses DefaultIDTokenClockSkew.
	ClockSkew time.Duration
}

// VerifyAuthorizationResponse checks a JARM authorization response and
// returns the parameters it carries: `code` and `state`, or `error` and
// `error_description`, plus `iss`. `aud` and `exp` are left out, having
// been checked. The checks are JARM §2.4's: an asymmetric signature from a
// key in Keys, `iss` equal to Issuer, `aud` containing ClientID, and an
// `exp` that hasn't passed.
//
// Every failure wraps ErrUnverifiedAuthorizationResponse, so a caller can
// tell a forged or stale response from an AS error with errors.Is. An AS
// error inside a good JWT is not a failure here: it comes back as the
// `error` parameter.
//
// A claim name repeated in the JWT (Keycloak 26 repeats `iss`) resolves to
// its last value, as encoding/json does, so the checks see what the
// parameters say.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.4
func VerifyAuthorizationResponse(ctx context.Context, req *VerifyAuthorizationResponseRequest) (url.Values, error) {
	if req == nil || req.Response == "" {
		return nil, fmt.Errorf("%w: no signed response", ErrUnverifiedAuthorizationResponse)
	}
	if req.Issuer == "" || req.ClientID == "" || req.Keys == nil {
		return nil, fmt.Errorf("%w: Issuer, ClientID and Keys are required", ErrUnverifiedAuthorizationResponse)
	}
	skew := req.ClockSkew
	if skew == 0 {
		skew = DefaultIDTokenClockSkew
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(req.Response, claims, func(t *jwt.Token) (any, error) {
		return idTokenKey(ctx, req.Keys, t)
	},
		jwt.WithValidMethods(idTokenAlgs),
		jwt.WithIssuer(req.Issuer),
		jwt.WithAudience(req.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(skew),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnverifiedAuthorizationResponse, err)
	}
	params := url.Values{}
	for name, v := range claims {
		if name == "aud" || name == "exp" {
			continue
		}
		if s, ok := v.(string); ok {
			params.Set(name, s)
		}
	}
	return params, nil
}

// isJARMResponseMode reports whether mode asks for a signed authorization
// response: jwt, or one of query.jwt, fragment.jwt and form_post.jwt.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.3
func isJARMResponseMode(mode string) bool {
	return mode == "jwt" || len(mode) > 4 && mode[len(mode)-4:] == ".jwt"
}

// isFragmentResponseMode reports whether mode puts the response in the
// URL fragment, which a browser never sends to the loopback server.
func isFragmentResponseMode(mode string) bool {
	return mode == "fragment" || mode == "fragment.jwt"
}
