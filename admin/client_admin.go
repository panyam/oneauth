package admin

import (
	"context"
	"errors"
	"time"
)

// ClientRegistrar is the transport-agnostic core of OneAuth's client
// administration surface — registration (RFC 7591 + the proprietary
// /apps/register path), listing, admin reads/deletes, and secret/key
// rotation. HTTP handlers in admin/ are thin wrappers around this interface
// (see DCRHandler.ServeHTTP and AppRegistrar.handleX), the same shape as
// ClientRegistrationManager (#168/#169/#170) for self-service management
// and the same convention apiauth/ adopts under #175.
//
// Auth boundary
//
// Methods on this interface are post-auth: the wrapper enforces AdminAuth
// (X-Admin-Key, etc.) before invoking the manager. ClientRegistrar itself
// is unauthenticated by design — it expresses *what* admin operations
// exist, not *who* may invoke them.
//
// Distinction from ClientRegistrationManager
//
// ClientRegistrationManager is the SELF-SERVICE management surface
// (RFC 7592, authed by registration_access_token) — only the registered
// client can act on its own registration. ClientRegistrar is the ADMIN
// surface — operators acting across all registrations. Same domain
// (registrations) but different security models, hence two interfaces.
//
// See: https://github.com/panyam/oneauth/issues/172
type ClientRegistrar interface {
	// Register handles RFC 7591 Dynamic Client Registration. The wire format
	// of the request and response is the RFC 7591 / 7592 client metadata
	// shape — RegisterRequest.Metadata is the standard DCR request body,
	// RegisterResponse.Registration is the standard DCR response body
	// (extended with the RFC 7592 §3 management credentials).
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)

	// RegisterLegacy handles the proprietary /apps/register path. Distinct
	// from Register because the wire shapes diverge — the legacy endpoint
	// carries OneAuth-specific quota fields (MaxRooms / MaxMsgRate) that
	// RFC 7591 has no place for. Eventual removal of this endpoint is
	// tracked under issue #189.
	RegisterLegacy(ctx context.Context, req *RegisterLegacyRequest) (*RegisterLegacyResponse, error)

	// ListClients returns every registration in the registry. Reads from
	// the in-memory cache hydrated from the AppRegistrationStore on
	// AppRegistrar construction.
	ListClients(ctx context.Context, req *ListClientsRequest) (*ListClientsResponse, error)

	// GetClient returns the registration for req.ClientID, or
	// ErrAppNotFound. This is the ADMIN read — distinct from
	// ClientRegistrationManager.GetRegistration which authenticates with
	// the client's own registration_access_token.
	GetClient(ctx context.Context, req *GetClientRequest) (*GetClientResponse, error)

	// DeleteClient removes the registration for req.ClientID and
	// invalidates its KeyStore entry. Returns ErrAppNotFound if the
	// client does not exist. This is the ADMIN delete — distinct from
	// ClientRegistrationManager.DeleteRegistration which authenticates
	// with the client's own token.
	DeleteClient(ctx context.Context, req *DeleteClientRequest) (*DeleteClientResponse, error)

	// RotateSecret rotates the signing key for req.ClientID. For symmetric
	// algorithms a fresh secret is generated and returned. For asymmetric
	// algorithms the caller MUST supply a new PublicKey (PEM) — there is
	// no server-side keypair generation today. When KidStore is configured
	// on AppRegistrar, the previous key is retained for the grace period
	// so in-flight tokens stay verifiable.
	RotateSecret(ctx context.Context, req *RotateSecretRequest) (*RotateSecretResponse, error)
}

// ----------------------------------------------------------------------------
// Register (RFC 7591 + RFC 7592 §3 management credentials)
// ----------------------------------------------------------------------------

// RegisterRequest is the input to ClientRegistrar.Register.
type RegisterRequest struct {
	// Metadata is the RFC 7591 §2 client metadata payload. Required.
	Metadata *DCRRequest

	// IssuerBaseURL is the public-facing AS base URL used to construct the
	// registration_client_uri returned in the response (RFC 7592 §3). When
	// empty, callers are expected to substitute a value (e.g., the HTTP
	// wrapper falls back to scheme + r.Host) before invoking the manager.
	IssuerBaseURL string
}

// RegisterResponse wraps the RFC 7591 / 7592 response body.
type RegisterResponse struct {
	Registration *DCRResponse
}

// ----------------------------------------------------------------------------
// RegisterLegacy (proprietary /apps/register)
// ----------------------------------------------------------------------------

// RegisterLegacyRequest carries the field set that the proprietary
// /apps/register endpoint accepts. Notable differences from RegisterRequest:
//   - ClientDomain replaces ClientName / ClientURI as the primary metadata
//   - MaxRooms / MaxMsgRate carry OneAuth-specific quota that DCR cannot express
//   - PublicKey is a raw PEM string for asymmetric algs (DCR uses JWKS instead)
type RegisterLegacyRequest struct {
	ClientDomain string  `json:"client_domain"`
	SigningAlg   string  `json:"signing_alg"` // empty → defaults to HS256
	PublicKey    string  `json:"public_key"`  // PEM-encoded; required for RS256/ES256
	MaxRooms     int     `json:"max_rooms"`
	MaxMsgRate   float64 `json:"max_msg_rate"`
}

// RegisterLegacyResponse wraps the proprietary response. Captured as
// concrete fields rather than a map so the wire shape is reviewable in one
// place; the HTTP wrapper marshals each field with the right name.
type RegisterLegacyResponse struct {
	ClientID     string    `json:"client_id"`
	ClientDomain string    `json:"client_domain"`
	SigningAlg   string    `json:"signing_alg"`
	ClientSecret string    `json:"client_secret,omitempty"` // present only for symmetric algs
	MaxRooms     int       `json:"max_rooms"`
	MaxMsgRate   float64   `json:"max_msg_rate"`
	CreatedAt    time.Time `json:"created_at"`
}

// ----------------------------------------------------------------------------
// ListClients
// ----------------------------------------------------------------------------

// ListClientsRequest is intentionally empty today — the proprietary endpoint
// has no filtering or pagination. Wrapper struct exists for the convention
// (ctx, *Req → *Resp, error) and so future fields (paging, filters) can be
// added without changing the method signature.
type ListClientsRequest struct{}

// ListClientsResponse returns every registration. Each entry is a clone —
// callers cannot mutate the in-memory cache via this value.
type ListClientsResponse struct {
	Apps []*AppRegistration
}

// ----------------------------------------------------------------------------
// GetClient (admin)
// ----------------------------------------------------------------------------

// GetClientRequest is the input to ClientRegistrar.GetClient.
type GetClientRequest struct {
	ClientID string
}

// GetClientResponse is the registration metadata for the requested client.
type GetClientResponse struct {
	Registration *AppRegistration
}

// ----------------------------------------------------------------------------
// DeleteClient (admin)
// ----------------------------------------------------------------------------

// DeleteClientRequest is the input to ClientRegistrar.DeleteClient.
type DeleteClientRequest struct {
	ClientID string
}

// DeleteClientResponse is intentionally empty — the proprietary endpoint
// returns {"deleted": true, "client_id": ...}, but that's a wire-format
// concern handled by the wrapper. The manager-level signal is "no error =
// success".
type DeleteClientResponse struct{}

// ----------------------------------------------------------------------------
// RotateSecret
// ----------------------------------------------------------------------------

// RotateSecretRequest is the input to ClientRegistrar.RotateSecret.
type RotateSecretRequest struct {
	ClientID string

	// PublicKey is the new public key in PEM form. Required for
	// asymmetric (RS256 / ES256 / etc.) clients; ignored for symmetric.
	PublicKey string

	// GracePeriod retains the OLD key in KidStore for this duration so
	// in-flight tokens signed with the previous material remain verifiable.
	// When zero, AppRegistrar.DefaultGracePeriod is used (default 24h).
	// Has no effect when KidStore is nil.
	GracePeriod time.Duration
}

// RotateSecretResponse is the new key material. Fields populated depend on
// the algorithm: ClientSecret only for symmetric, PreviousKid + GracePeriod
// only when KidStore retained the old key.
type RotateSecretResponse struct {
	ClientID     string
	ClientSecret string        // present only for symmetric algs
	Kid          string        // computed from the new key material
	PreviousKid  string        // only when the previous key was retained
	GracePeriod  time.Duration // grace period actually applied
}

// ErrInvalidPublicKey indicates that a provided PEM public key failed
// parsing or did not match the registered signing algorithm. Wrapper
// layers map this to HTTP 400 invalid_request.
var ErrInvalidPublicKey = errors.New("invalid public key")

// ErrPublicKeyRequired indicates that an asymmetric registration or
// rotation was attempted without supplying the public_key field.
// Wrapper layers map this to HTTP 400 invalid_request.
var ErrPublicKeyRequired = errors.New("public key required for asymmetric algorithm")
