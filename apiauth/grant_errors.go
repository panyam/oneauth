package apiauth

import (
	"errors"
	"net/http"
)

// GrantError carries the RFC 6749 §5.2 error code + description + the
// HTTP status the token endpoint should return. The new grant impls
// (AuthorizationCodeGranter / DeviceCodeGranter /
// JwtBearerGranter / TokenExchanger) return this typed error so
// the HTTP shim in TokenEndpointHandler can `errors.As` and map to
// the proper application/json + status response without the impls
// themselves owning HTTP concerns.
//
// Code is one of the canonical RFC 6749 §5.2 / RFC 8628 §3.5 strings
// (`invalid_request`, `invalid_grant`, `unsupported_grant_type`,
// `invalid_client`, `slow_down`, `authorization_pending`,
// `access_denied`, `expired_token`, `server_error`).
type GrantError struct {
	Code        string
	Description string
	Status      int
}

// Error implements the error interface. The message is intentionally
// short — RFC 6749 §5.2 reports the code + description in the JSON
// body; this string is for logs.
func (e *GrantError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// invalidRequest returns a 400 invalid_request error. Used by the
// grant impls when the request shape is wrong (missing required
// parameter, malformed value).
func invalidRequest(description string) *GrantError {
	return &GrantError{Code: "invalid_request", Description: description, Status: http.StatusBadRequest}
}

// invalidGrant returns a 400 invalid_grant error. Used when the
// supplied credential (code, refresh_token, device_code, assertion)
// is unknown, expired, mismatched, or otherwise unredeemable.
func invalidGrant(description string) *GrantError {
	return &GrantError{Code: "invalid_grant", Description: description, Status: http.StatusBadRequest}
}

// invalidClient returns a 401 invalid_client error. Used when client
// authentication fails or the registered client cannot be resolved.
func invalidClient(description string) *GrantError {
	return &GrantError{Code: "invalid_client", Description: description, Status: http.StatusUnauthorized}
}

// unsupportedGrantType returns a 400 unsupported_grant_type error.
// Used when a grant's required dependencies are not configured on
// the OneAuth instance (e.g. AuthorizationCodeStore is nil but a
// client tries grant_type=authorization_code).
func unsupportedGrantType(description string) *GrantError {
	return &GrantError{Code: "unsupported_grant_type", Description: description, Status: http.StatusBadRequest}
}

// serverError returns a 500 server_error. Used for unexpected
// internal failures the client cannot meaningfully react to.
func serverError(description string) *GrantError {
	return &GrantError{Code: "server_error", Description: description, Status: http.StatusInternalServerError}
}

// asGrantError attempts to cast err to *GrantError. Returns the
// pointer + true on hit; nil + false otherwise. Convenience wrapper
// over `errors.As` since `errors.As` requires an addressable target.
func asGrantError(err error) (*GrantError, bool) {
	var ge *GrantError
	if errors.As(err, &ge) {
		return ge, true
	}
	return nil, false
}
