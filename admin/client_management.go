package admin

import (
	"context"
	"errors"
)

// ClientRegistrationManager is the transport-agnostic core of OAuth 2.0
// Dynamic Client Registration Management (RFC 7592). HTTP handlers in admin/
// (and any future gRPC / in-process callers) are thin wrappers around this
// interface — they parse the request, call into the manager, then format the
// response. Mirrors the apiauth/ pattern (TokenIssuer / TokenValidator /
// TokenIntrospector / TokenRevoker — see issue #110).
//
// Method shape — every method follows the convention:
//
//	MethodName(ctx context.Context, req *XRequest) (*XResponse, error)
//
// Two-arg / two-return signatures map cleanly to gRPC codegen if we ever
// generate stubs from these interfaces. The first parameter is plain
// context.Context for now; a typed library context (carrying stores,
// loggers, request-scoped deps) can replace it later without changing the
// shape — that's the point of standardizing on a single ctx parameter
// rather than expanding the parameter list ad hoc.
//
// #168 ships GetRegistration. #169 ships UpdateRegistration. #170 ships
// DeleteRegistration — completing the verb trio.
type ClientRegistrationManager interface {
	// GetRegistration returns the registration for req.ClientID iff
	// req.AccessToken matches its stored registration_access_token. Any
	// auth failure — wrong token, missing token, unknown client_id — yields
	// ErrUnauthorized so callers (and attackers) cannot distinguish them.
	GetRegistration(ctx context.Context, req *GetRegistrationRequest) (*GetRegistrationResponse, error)

	// UpdateRegistration replaces the metadata for req.ClientID per RFC 7592
	// §2.2 (full replacement, not PATCH-style merge). The request's body-level
	// client_id (req.Metadata.ClientID) MUST equal req.ClientID — mismatch
	// returns ErrInvalidClientMetadata, mapped to HTTP 400 by the wrapper.
	// Auth failures return ErrUnauthorized as with GetRegistration.
	//
	// On success the registration_access_token is rotated (RFC 7592 §2.2
	// recommended) and the new token is returned in the response; the old
	// token is invalid for any subsequent management request.
	//
	// Out of scope for #169: changing token_endpoint_auth_method (which would
	// require re-keying / new secret). Such requests return
	// ErrInvalidClientMetadata. Clients that need to change auth method
	// DELETE and re-register.
	UpdateRegistration(ctx context.Context, req *UpdateRegistrationRequest) (*UpdateRegistrationResponse, error)

	// DeleteRegistration removes the registration for req.ClientID iff
	// req.AccessToken matches the stored registration_access_token, and
	// invalidates the client's signing credentials so already-issued tokens
	// fail subsequent validation (RFC 7592 §2.3 — "the authorization server
	// MUST invalidate" all tokens for the deleted client). The same uniform
	// ErrUnauthorized envelope as the other methods covers every auth failure.
	//
	// Idempotency is intentional but limited: a second DELETE on the same
	// client_id returns ErrUnauthorized (the registration is gone, so the
	// token check fails at lookup) rather than a special "already deleted"
	// error — preserves the no-enumeration guard.
	DeleteRegistration(ctx context.Context, req *DeleteRegistrationRequest) (*DeleteRegistrationResponse, error)
}

// GetRegistrationRequest is the input to ClientRegistrationManager.GetRegistration.
type GetRegistrationRequest struct {
	// ClientID identifies the registration to read.
	ClientID string

	// AccessToken is the registration_access_token issued at registration time
	// (RFC 7592 §3). Must match the value stored on the registration.
	AccessToken string
}

// GetRegistrationResponse wraps the registration metadata. Wrapped (rather than
// returning *DCRResponse directly) so that future forward-compat fields can be
// added without changing the method signature — same reason gRPC requires
// dedicated response messages per method.
type GetRegistrationResponse struct {
	Registration *DCRResponse
}

// UpdateRegistrationRequest is the input to ClientRegistrationManager.UpdateRegistration.
type UpdateRegistrationRequest struct {
	// ClientID identifies the registration to update. The wrapper guarantees
	// this matches Metadata.ClientID before invoking the manager.
	ClientID string

	// AccessToken is the registration_access_token issued at registration time
	// (or the rotated value from a previous UpdateRegistration). Must match
	// the value currently stored on the registration.
	AccessToken string

	// Metadata is the RFC 7591 / 7592 client metadata to replace the existing
	// registration with. Treated as a full-replacement payload per
	// RFC 7592 §2.2 — fields omitted from Metadata are cleared on the server.
	Metadata *DCRRequest
}

// UpdateRegistrationResponse wraps the post-update registration. Registration
// includes the rotated registration_access_token, which supersedes the one
// passed in via the request. Callers MUST persist the new token before
// discarding the old one.
type UpdateRegistrationResponse struct {
	Registration *DCRResponse
}

// DeleteRegistrationRequest is the input to ClientRegistrationManager.DeleteRegistration.
type DeleteRegistrationRequest struct {
	// ClientID identifies the registration to remove.
	ClientID string

	// AccessToken is the registration_access_token currently on the
	// registration — must match for the deletion to be authorized.
	AccessToken string
}

// DeleteRegistrationResponse is intentionally empty today: RFC 7592 §2.3
// returns 204 No Content with no body. The struct exists so future
// forward-compat fields (e.g., a deletion confirmation token) can be added
// without changing the method signature — same rationale as the other
// response types.
type DeleteRegistrationResponse struct{}

// ErrUnauthorized is the single failure mode returned by ClientRegistrationManager
// for any authentication problem on the management protocol. The uniform error
// is intentional: distinguishing "unknown client_id" from "wrong token" would
// turn /apps/dcr/{client_id} into a probe for valid identifiers.
var ErrUnauthorized = errors.New("unauthorized registration management request")

// ErrInvalidClientMetadata signals that a management request was authenticated
// successfully but the request body fails RFC 7591 / 7592 client-metadata
// validation. HTTP wrappers map this to 400 Bad Request. Distinct from
// ErrUnauthorized because, by the time we get here, the caller has already
// proven possession of the registration access token — refusing to distinguish
// would be needlessly cryptic.
var ErrInvalidClientMetadata = errors.New("invalid client metadata")
