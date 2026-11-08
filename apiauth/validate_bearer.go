package apiauth

import (
	"context"
	"errors"

	"github.com/panyam/oneauth/core"
)

// ValidateBearerRequest is a token that arrived without an HTTP request
// around it, such as a fresh access token sent over an open WebSocket.
type ValidateBearerRequest struct {
	// Token is the access token or API key, without any scheme prefix.
	Token string

	// ConfirmBinding decides whether a token carrying an RFC 7800 `cnf`
	// claim may be used here. It is called only for such tokens, after the
	// token itself has passed every other check, with the token's `cnf`.
	// Returning nil accepts the token.
	//
	// A bare token has no request for a DPoP proof to sign, so oneauth can
	// not check the binding itself, and with ConfirmBinding nil every bound
	// token is refused. A host supplies the check that fits its channel.
	// One example is a WebSocket whose upgrade request carried a verified
	// DPoP proof: it can require the new token's cnf.jkt to equal the key
	// that upgrade proved. Returning nil without checking anything accepts
	// a stolen bound token as a bearer token, the downgrade RFC 9449 §7.2
	// exists to close.
	//
	// An *AuthError returned here reaches the caller unchanged, so a host
	// that checks its own proofs can answer "invalid_dpop_proof" or
	// "use_dpop_nonce". Any other error is wrapped as "invalid_token".
	ConfirmBinding func(ctx context.Context, cnf *core.Confirmation) error
}

// ValidateBearerResponse carries what the validated token says about its
// bearer.
type ValidateBearerResponse struct {
	Info *TokenInfo
}

// ValidateBearer validates a token the way ValidateToken validates one on a
// request: API key, then local JWT, then introspection, with the same
// issuer, audience, expiry, kind and revocation checks. It returns the same
// TokenInfo the request path puts in the context.
//
// Every failure is an *AuthError. A token that fails validation, an empty
// token and a nil request give Code "invalid_token" with Scheme
// TokenTypeBearer. Key-binding failures give Scheme TokenTypeDPoP. Those are
// a bound token with no ConfirmBinding, a ConfirmBinding refusal, and an
// unbound token while RequireDPoP is in force.
//
// Unlike the request path, a bound token is refused even when DPoP is nil.
// A resource server without a DPoP validator accepts a bound token presented
// under the Bearer scheme, as RFC 9449 §7.2 permits. ValidateBearer is new,
// and has ConfirmBinding as its way to accept one, so it takes the safe side.
//
// RequireDPoP applies as it does on the request path, and only when DPoP is
// set. An unbound token is then refused even with ConfirmBinding supplied.
func (m *APIMiddleware) ValidateBearer(ctx context.Context, req *ValidateBearerRequest) (*ValidateBearerResponse, error) {
	if req == nil || req.Token == "" {
		return nil, &AuthError{Scheme: TokenTypeBearer, Code: "invalid_token", Description: "empty token"}
	}

	info, err := m.authenticateToken(ctx, TokenTypeBearer, req.Token)
	if err != nil {
		return nil, err
	}

	if info.Confirmation.IsEmpty() {
		if m.DPoP != nil && m.RequireDPoP {
			return nil, &AuthError{
				Scheme:      TokenTypeDPoP,
				Code:        "invalid_token",
				Description: "this resource requires a DPoP-bound access token",
			}
		}
		return &ValidateBearerResponse{Info: info}, nil
	}

	if req.ConfirmBinding == nil {
		return nil, &AuthError{
			Scheme:      TokenTypeDPoP,
			Code:        "invalid_token",
			Description: "DPoP-bound token presented as a bearer token",
		}
	}
	if err := req.ConfirmBinding(ctx, info.Confirmation); err != nil {
		var ae *AuthError
		if errors.As(err, &ae) {
			return nil, err
		}
		return nil, &AuthError{Scheme: TokenTypeDPoP, Code: "invalid_token", Description: "Invalid DPoP key binding", Err: err}
	}
	return &ValidateBearerResponse{Info: info}, nil
}
