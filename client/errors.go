package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ErrLoginTimeout is returned by LoginWithBrowser when no callback reaches
// the loopback listener within BrowserLoginRequest.Timeout. The returned
// error wraps it with the timeout ("login timed out after 5m0s"), so match it
// with errors.Is. Cancelling the caller's ctx returns ctx.Err() instead, so a
// caller can tell "the user walked away" from "we gave up".
var ErrLoginTimeout = errors.New("login timed out")

// AuthorizeError is an error response from the authorization endpoint
// itself, before any redirect back to the client: the AS refused to start
// the flow, e.g. an unknown client_id or an unregistered redirect_uri
// (RFC 6749 §4.1.2.1 says the AS must not redirect in those cases).
// FollowRedirects and ApproveConsent return it when /authorize ends with a
// status of 400 or above anywhere other than the redirect_uri, and
// LoginWithBrowser passes it on wrapped in a *BrowserOpenError, so use
// errors.As to find it.
//
// Code and Description are the OAuth error and error_description when the
// body is a JSON error object. Many servers answer with an HTML page
// instead (Keycloak does); then Code is empty and Body holds a short
// whitespace-collapsed snippet of the page.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
type AuthorizeError struct {
	Status      int
	Code        string
	Description string
	Body        string
}

// Error renders the status plus the OAuth error (or body snippet), e.g.
// "authorization endpoint answered 400 Bad Request: invalid_client: unknown client".
func (e *AuthorizeError) Error() string {
	status := fmt.Sprintf("%d %s", e.Status, http.StatusText(e.Status))
	if http.StatusText(e.Status) == "" {
		status = fmt.Sprintf("%d", e.Status)
	}
	detail := e.Body
	if e.Code != "" {
		detail = e.Code
		if e.Description != "" {
			detail += ": " + e.Description
		}
	}
	if detail == "" {
		return "authorization endpoint answered " + status
	}
	return "authorization endpoint answered " + status + ": " + detail
}

// CallbackError is an error delivered to the loopback redirect_uri: the AS
// started the flow but ended it with ?error=... instead of a code. Code is
// the RFC 6749 §4.1.2.1 error code; "access_denied" means the user declined,
// which a caller should not answer by opening the consent page again.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
type CallbackError struct {
	Code        string
	Description string
}

// Error renders "authorization error: <code>: <description>".
func (e *CallbackError) Error() string {
	return fmt.Sprintf("authorization error: %s: %s", e.Code, e.Description)
}

// TokenError is a failed response from a token endpoint, returned by every
// grant this package drives: LoginWithBrowser's code exchange, Login,
// ClientCredentials, RefreshToken, JwtBearerGrant, TokenExchange and
// PollDeviceToken. It is usually wrapped, so match it with errors.As.
//
// Code and Description are the RFC 6749 §5.2 error and error_description.
// Code is empty when the body is not a JSON error object (a proxy's 502
// page, say); Status still carries the HTTP status. PollDeviceToken keeps
// returning its RFC 8628 sentinels (ErrAuthorizationPending and friends)
// for the four codes that drive its polling loop, and a *TokenError for the
// rest.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
type TokenError struct {
	Status      int
	Code        string
	Description string

	// message, when set, is the text the returning call has always used,
	// kept so log lines and string matches don't change.
	message string
}

// Error renders "<code>: <description>", or "token endpoint returned
// <status>" when the response carried no error code. Some calls keep an
// older wording of their own.
func (e *TokenError) Error() string {
	switch {
	case e.message != "":
		return e.message
	case e.Code == "":
		return fmt.Sprintf("token endpoint returned %d", e.Status)
	case e.Description == "":
		return e.Code
	default:
		return e.Code + ": " + e.Description
	}
}

// BrowserOpenError is returned by LoginWithBrowser when the
// BrowserLoginRequest.OpenBrowser function fails: no browser to launch, or
// a headless opener that could not complete the authorization request (a
// consent form with no approve button). Err is the opener's error, and
// Unwrap exposes it, so errors.As still finds an *AuthorizeError returned
// by FollowRedirects or ApproveConsent.
type BrowserOpenError struct {
	URL string
	Err error
}

// Error renders "failed to open browser (URL: <url>): <err>".
func (e *BrowserOpenError) Error() string {
	return fmt.Sprintf("failed to open browser (URL: %s): %v", e.URL, e.Err)
}

// Unwrap returns the opener's error.
func (e *BrowserOpenError) Unwrap() error { return e.Err }

// newTokenError reads the RFC 6749 §5.2 error object out of a failed token
// response body. A body that isn't one leaves Code and Description empty.
func newTokenError(status int, body []byte) *TokenError {
	var parsed struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &parsed)
	return &TokenError{Status: status, Code: parsed.Error, Description: parsed.Description}
}

// authenticationFailed is the TokenError for the form and JSON token paths
// on AuthClient, keeping their "authentication failed: ..." wording, which
// names the description when there is one and the code otherwise.
func authenticationFailed(status int, body []byte) *TokenError {
	e := newTokenError(status, body)
	switch {
	case e.Description != "":
		e.message = "authentication failed: " + e.Description
	case e.Code != "":
		e.message = "authentication failed: " + e.Code
	default:
		e.message = fmt.Sprintf("authentication failed: HTTP %d", status)
	}
	return e
}
