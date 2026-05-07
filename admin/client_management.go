package admin

import "errors"

// ClientRegistrationManager is the transport-agnostic core of OAuth 2.0
// Dynamic Client Registration Management (RFC 7592). HTTP handlers in admin/
// (and any future gRPC / in-process callers) are thin wrappers around this
// interface — they parse the request, call into the manager, then format the
// response. Mirrors the apiauth/ pattern (TokenIssuer / TokenValidator /
// TokenIntrospector / TokenRevoker — see issue #110).
//
// Issue #168 ships GetRegistration. UpdateRegistration / DeleteRegistration
// arrive in #169 / #170.
type ClientRegistrationManager interface {
	// GetRegistration returns the registration for clientID iff accessToken
	// matches its stored registration_access_token. Returns ErrUnauthorized
	// for any failure mode — wrong token, missing token, unknown client_id —
	// so callers (and attackers) cannot distinguish them.
	GetRegistration(clientID, accessToken string) (*DCRResponse, error)
}

// ErrUnauthorized is the single failure mode returned by ClientRegistrationManager
// for any authentication problem on the management protocol. The uniform error
// is intentional: distinguishing "unknown client_id" from "wrong token" would
// turn /apps/dcr/{client_id} into a probe for valid identifiers.
var ErrUnauthorized = errors.New("unauthorized registration management request")
