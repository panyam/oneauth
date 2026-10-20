package core

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrAuthorizationCodeNotFound is returned by AuthorizationCodeStore.Get
// and Delete when no record matches the supplied code. Distinct from
// "expired" — an expired record may still exist in the store until
// CleanupExpired runs, and the token-endpoint redemption handler must
// surface a different error to the caller in each case.
var ErrAuthorizationCodeNotFound = errors.New("authorization code not found")

// ErrAuthorizationCodeUsed is returned by
// AuthorizationCodeStore.ConsumeAuthorizationCode when the code was
// already redeemed. The response still carries the record, with the
// tokens the first redemption recorded, so the caller can revoke them
// (RFC 6749 §4.1.2).
var ErrAuthorizationCodeUsed = errors.New("authorization code already used")

// AuthorizationCode is one issued RFC 6749 §4.1 authorization code,
// minted by the AS at the end of a successful /authorize consent and
// redeemed at the token endpoint via `grant_type=authorization_code`.
//
// The struct captures every binding the redemption path enforces:
// client_id (§4.1.3 "MUST be issued to the requesting client"),
// redirect_uri (§4.1.3 "MUST be identical to the value included in the
// initial authorization request"), PKCE challenge (RFC 7636 §4.6),
// scopes carried forward to the issued access token, and the subject
// the resource owner consented as.
//
// Codes are single-use. Redemption marks the record used
// (ConsumeAuthorizationCode) rather than deleting it, and keeps it until
// the access token it produced expires, so a second redemption can find
// and revoke that token (RFC 6749 §4.1.2). RFC 6749 §4.1.2 mandates
// short lifetimes (≤10 minutes); the apiauth handler defaults to 60
// seconds, which matches OAuth 2.1.
type AuthorizationCode struct {
	// Code is the high-entropy identifier the client redeems with.
	// 256-bit, hex-encoded; unguessable.
	Code string `json:"code"`

	// ClientID is the OAuth client the code was issued to. RFC 6749
	// §4.1.3 requires the redemption request's authenticated client_id
	// to match this value.
	ClientID string `json:"client_id"`

	// RedirectURI is the verbatim redirect_uri parameter from the
	// initial /authorize request. The redemption handler requires the
	// token request to send the same value (RFC 6749 §4.1.3).
	RedirectURI string `json:"redirect_uri"`

	// Scopes is the granted scope set, carried forward unchanged to the
	// issued access token. The consent UI may narrow this set relative
	// to the requested scopes.
	Scopes []string `json:"scopes,omitempty"`

	// Subject is the principal (RFC 7519 `sub`) who approved the
	// authorization. Bound to the issued access token.
	Subject string `json:"subject"`

	// CodeChallenge is the PKCE challenge (RFC 7636 §4.2) the client
	// committed to at /authorize time. Empty when the client did not
	// supply PKCE; the apiauth handler rejects empty challenges by
	// default (OAuth 2.1 makes PKCE mandatory for public clients and
	// SHOULD-mandatory for all clients).
	CodeChallenge string `json:"code_challenge,omitempty"`

	// DPoPJKT is the RFC 7638 thumbprint of the DPoP key the client
	// named in the `dpop_jkt` authorization request parameter, empty
	// when the client sent none (RFC 9449 §10).
	//
	// When set, the token request redeeming this code MUST carry a DPoP
	// proof for the same key. That extends the binding back across the
	// front channel: without it the key first appears at the token
	// endpoint, so an intercepted code can be redeemed with the
	// attacker's key and yields a token bound to the attacker.
	//
	// The protection only holds when the client uses a fresh key per
	// authorization request, which §10 states plainly. A client reusing
	// one key gains nothing here that PKCE does not already give it.
	DPoPJKT string `json:"dpop_jkt,omitempty"`

	// CodeChallengeMethod is the transformation the client applied to
	// the verifier — "S256" (RFC 7636 §4.2) or "plain". Only S256 is
	// advertised in AS metadata; "plain" is rejected by the apiauth
	// handler.
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// AuthorizationDetails carries the RFC 9396 fine-grained
	// authorization payload from /authorize through to the issued
	// access token. Nil when the request had no authorization_details.
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`

	// Nonce is the OIDC Core §3.1.2.1 `nonce` request parameter, echoed
	// into the ID token the redemption issues (§3.1.3.6) so the client
	// can tie that ID token to its own authorization request. Empty when
	// the client sent none.
	Nonce string `json:"nonce,omitempty"`

	// AuthTime is when the user last authenticated, the ID token's
	// `auth_time` claim (OIDC Core §2). Zero when the deployment does not
	// know, in which case the claim is left out.
	AuthTime time.Time `json:"auth_time,omitempty"`

	// IssuedAt is when the AS minted the code. Useful for telemetry
	// and as the anchor for any future "max code age" enforcement.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is the deadline after which a redemption returns
	// invalid_grant. RFC 6749 §4.1.2 recommends ≤10 minutes; the
	// apiauth handler defaults to 60s (OAuth 2.1 alignment).
	ExpiresAt time.Time `json:"expires_at"`

	// UsedAt is when the code was redeemed, zero while it is unused. Set
	// once, by ConsumeAuthorizationCode.
	UsedAt time.Time `json:"used_at,omitempty"`

	// IssuedTokenID is the `jti` of the access token the redemption
	// minted, and IssuedTokenExpiresAt its expiry. The store keeps a used
	// record until IssuedTokenExpiresAt, after which there is nothing
	// left to revoke.
	IssuedTokenID        string    `json:"issued_token_id,omitempty"`
	IssuedTokenExpiresAt time.Time `json:"issued_token_expires_at,omitempty"`

	// IssuedRefreshFamily is the family of the refresh token the
	// redemption minted, empty when it minted none.
	IssuedRefreshFamily string `json:"issued_refresh_family,omitempty"`

	// ReuseDetected is set when the code is presented after it was used.
	// The redemption that minted the tokens checks it after recording
	// them, so a reuse racing the first redemption still revokes.
	ReuseDetected bool `json:"reuse_detected,omitempty"`
}

// IsExpired reports whether the code is past its deadline. Centralized
// here so the store, the redemption handler, and the cleanup pass agree
// on the comparison.
func (a *AuthorizationCode) IsExpired(now time.Time) bool {
	return !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt)
}

// IsUsed reports whether the code has been redeemed.
func (a *AuthorizationCode) IsUsed() bool {
	return !a.UsedAt.IsZero()
}

// RetainUntil is when CleanupExpired may remove the record: the code's
// own expiry, or for a used code the later of that and the expiry of the
// access token it produced.
func (a *AuthorizationCode) RetainUntil() time.Time {
	if a.IsUsed() && a.IssuedTokenExpiresAt.After(a.ExpiresAt) {
		return a.IssuedTokenExpiresAt
	}
	return a.ExpiresAt
}

// CreateAuthorizationCodeRequest carries the inputs for persisting a
// freshly-minted authorization code. The handler computes the code,
// timestamps, and binding; the store persists.
type CreateAuthorizationCodeRequest struct {
	Code *AuthorizationCode
}

// CreateAuthorizationCodeResponse is empty — CreateAuthorizationCode
// returns success/failure via the error.
type CreateAuthorizationCodeResponse struct{}

// GetAuthorizationCodeRequest carries the code to look up.
type GetAuthorizationCodeRequest struct {
	Code string
}

// GetAuthorizationCodeResponse wraps the requested code binding.
type GetAuthorizationCodeResponse struct {
	Code *AuthorizationCode
}

// DeleteAuthorizationCodeRequest carries the code to remove. The
// redemption handler deletes an expired code it was handed; a redeemed
// code is marked used instead (ConsumeAuthorizationCode).
type DeleteAuthorizationCodeRequest struct {
	Code string
}

// DeleteAuthorizationCodeResponse is empty.
type DeleteAuthorizationCodeResponse struct{}

// ConsumeAuthorizationCodeRequest carries the code being redeemed.
type ConsumeAuthorizationCodeRequest struct {
	Code string
}

// ConsumeAuthorizationCodeResponse carries the record as it was before
// the call: unused on success, or, with ErrAuthorizationCodeUsed, the
// first redemption's recorded tokens.
type ConsumeAuthorizationCodeResponse struct {
	Code *AuthorizationCode
}

// RecordAuthorizationCodeTokensRequest names the tokens a redemption
// minted from Code.
type RecordAuthorizationCodeTokensRequest struct {
	Code           string
	TokenID        string
	TokenExpiresAt time.Time
	RefreshFamily  string
}

// RecordAuthorizationCodeTokensResponse reports whether the code was
// presented again before the tokens were recorded.
type RecordAuthorizationCodeTokensResponse struct {
	ReuseDetected bool
}

// CleanupExpiredAuthorizationCodesRequest is empty; the call enumerates
// the store and removes anything past its expiry.
type CleanupExpiredAuthorizationCodesRequest struct{}

// CleanupExpiredAuthorizationCodesResponse reports how many records
// were removed. Useful for telemetry / log-line metrics.
type CleanupExpiredAuthorizationCodesResponse struct {
	Removed int
}

// AuthorizationCodeStore persists RFC 6749 §4.1 authorization codes.
//
// Backends ship in lock-step with the other store interfaces:
// InMemoryAuthorizationCodeStore (below) is the in-process default.
// FS / GORM / GAE backends follow the same pattern established by
// DeviceAuthorizationStore (issues 269 / 270) and are deferred to
// follow-ups.
//
// Redemption is a two-step protocol, both steps atomic per record:
// ConsumeAuthorizationCode marks the code used (the single-use gate),
// and RecordAuthorizationCodeTokens stores what the redemption minted.
// A second Consume flags the record and returns those tokens so the
// caller can revoke them; a Record that finds the flag tells its caller
// to revoke its own. Whichever of the two runs second sees the other's
// write, so a reuse racing the first redemption is still caught.
type AuthorizationCodeStore interface {
	// CreateAuthorizationCode inserts a new authorization code. The
	// Code field MUST be unique across all non-expired records — the
	// caller has already generated it via cryptographic RNG, so a
	// collision is a programmer error and surfaces as a generic error
	// (not a typed sentinel). Mirrors the DeviceAuthorizationStore
	// collision contract.
	CreateAuthorizationCode(ctx context.Context, req *CreateAuthorizationCodeRequest) (*CreateAuthorizationCodeResponse, error)

	// GetAuthorizationCode returns the binding for the given code, or
	// ErrAuthorizationCodeNotFound. Does NOT filter by expiry — the
	// caller (the token endpoint handler) checks IsExpired so it can
	// surface a distinct invalid_grant vs expired error.
	GetAuthorizationCode(ctx context.Context, req *GetAuthorizationCodeRequest) (*GetAuthorizationCodeResponse, error)

	// DeleteAuthorizationCode removes the binding. Called by the token
	// endpoint on an expired code and by callers cleaning up rejected
	// flows. Returns ErrAuthorizationCodeNotFound when no record matches.
	DeleteAuthorizationCode(ctx context.Context, req *DeleteAuthorizationCodeRequest) (*DeleteAuthorizationCodeResponse, error)

	// ConsumeAuthorizationCode marks an unused code used and returns the
	// record as it was. For a code already used it sets ReuseDetected and
	// returns ErrAuthorizationCodeUsed together with the record, whose
	// Issued* fields name the tokens to revoke. A missing code is
	// ErrAuthorizationCodeNotFound.
	ConsumeAuthorizationCode(ctx context.Context, req *ConsumeAuthorizationCodeRequest) (*ConsumeAuthorizationCodeResponse, error)

	// RecordAuthorizationCodeTokens stores the tokens a redemption minted
	// on the used record and reports ReuseDetected, read in the same
	// atomic step. A missing code is ErrAuthorizationCodeNotFound.
	RecordAuthorizationCodeTokens(ctx context.Context, req *RecordAuthorizationCodeTokensRequest) (*RecordAuthorizationCodeTokensResponse, error)

	// CleanupExpired removes every record whose RetainUntil is at or
	// before the current wall-clock time, so a used code outlives its own
	// expiry until the access token it produced has expired. Production
	// deployments run this on a timer; tests call it explicitly.
	CleanupExpired(ctx context.Context, req *CleanupExpiredAuthorizationCodesRequest) (*CleanupExpiredAuthorizationCodesResponse, error)
}

// InMemoryAuthorizationCodeStore is a process-local
// AuthorizationCodeStore. State is lost on restart — suitable for
// tests, single-process dev, and the in-memory mode of the reference
// server. Production deployments use a persistent backend.
type InMemoryAuthorizationCodeStore struct {
	mu     sync.RWMutex
	byCode map[string]*AuthorizationCode
}

// NewInMemoryAuthorizationCodeStore returns an empty store.
func NewInMemoryAuthorizationCodeStore() *InMemoryAuthorizationCodeStore {
	return &InMemoryAuthorizationCodeStore{byCode: map[string]*AuthorizationCode{}}
}

func (s *InMemoryAuthorizationCodeStore) CreateAuthorizationCode(_ context.Context, req *CreateAuthorizationCodeRequest) (*CreateAuthorizationCodeResponse, error) {
	if req == nil || req.Code == nil {
		return nil, errors.New("CreateAuthorizationCode: code is required")
	}
	c := req.Code
	if c.Code == "" {
		return nil, errors.New("CreateAuthorizationCode: code value is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byCode[c.Code]; ok {
		return nil, errors.New("CreateAuthorizationCode: code collision")
	}
	clone := *c
	s.byCode[c.Code] = &clone
	return &CreateAuthorizationCodeResponse{}, nil
}

func (s *InMemoryAuthorizationCodeStore) GetAuthorizationCode(_ context.Context, req *GetAuthorizationCodeRequest) (*GetAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, ErrAuthorizationCodeNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.byCode[req.Code]
	if !ok {
		return nil, ErrAuthorizationCodeNotFound
	}
	clone := *c
	return &GetAuthorizationCodeResponse{Code: &clone}, nil
}

func (s *InMemoryAuthorizationCodeStore) DeleteAuthorizationCode(_ context.Context, req *DeleteAuthorizationCodeRequest) (*DeleteAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, ErrAuthorizationCodeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byCode[req.Code]; !ok {
		return nil, ErrAuthorizationCodeNotFound
	}
	delete(s.byCode, req.Code)
	return &DeleteAuthorizationCodeResponse{}, nil
}

// ConsumeAuthorizationCode marks the code used under the store's lock;
// see AuthorizationCodeStore.
func (s *InMemoryAuthorizationCodeStore) ConsumeAuthorizationCode(_ context.Context, req *ConsumeAuthorizationCodeRequest) (*ConsumeAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, ErrAuthorizationCodeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byCode[req.Code]
	if !ok {
		return nil, ErrAuthorizationCodeNotFound
	}
	before := *c
	if c.IsUsed() {
		c.ReuseDetected = true
		return &ConsumeAuthorizationCodeResponse{Code: &before}, ErrAuthorizationCodeUsed
	}
	c.UsedAt = time.Now()
	return &ConsumeAuthorizationCodeResponse{Code: &before}, nil
}

// RecordAuthorizationCodeTokens stores the minted tokens under the
// store's lock; see AuthorizationCodeStore.
func (s *InMemoryAuthorizationCodeStore) RecordAuthorizationCodeTokens(_ context.Context, req *RecordAuthorizationCodeTokensRequest) (*RecordAuthorizationCodeTokensResponse, error) {
	if req == nil || req.Code == "" {
		return nil, ErrAuthorizationCodeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byCode[req.Code]
	if !ok {
		return nil, ErrAuthorizationCodeNotFound
	}
	c.IssuedTokenID = req.TokenID
	c.IssuedTokenExpiresAt = req.TokenExpiresAt
	c.IssuedRefreshFamily = req.RefreshFamily
	return &RecordAuthorizationCodeTokensResponse{ReuseDetected: c.ReuseDetected}, nil
}

// CleanupExpired removes records past their RetainUntil.
func (s *InMemoryAuthorizationCodeStore) CleanupExpired(_ context.Context, _ *CleanupExpiredAuthorizationCodesRequest) (*CleanupExpiredAuthorizationCodesResponse, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for code, c := range s.byCode {
		if !now.Before(c.RetainUntil()) {
			delete(s.byCode, code)
			removed++
		}
	}
	return &CleanupExpiredAuthorizationCodesResponse{Removed: removed}, nil
}
