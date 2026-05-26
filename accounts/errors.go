package accounts

import "net/http"

// AuthError represents a structured authentication error surfaced to a user.
// Used by both local (username/password) and federated (OAuth/SAML) flows
// when account-level constraints fail — taken email, duplicate username,
// weak password, etc.
type AuthError struct {
	Code    string // "email_exists", "username_taken", "weak_password", "invalid_format", etc.
	Message string // Human-readable message
	Field   string // Which form field has the error (e.g., "email", "username", "password")
}

func (e *AuthError) Error() string {
	return e.Message
}

// Common error codes.
const (
	ErrCodeEmailExists     = "email_exists"
	ErrCodeUsernameTaken   = "username_taken"
	ErrCodeWeakPassword    = "weak_password"
	ErrCodeInvalidUsername = "invalid_username"
	ErrCodeInvalidEmail    = "invalid_email"
	ErrCodeInvalidPhone    = "invalid_phone"
	ErrCodeMissingField    = "missing_field"
	ErrCodeInvalidCreds    = "invalid_credentials"
)

// NewAuthError creates a new AuthError.
func NewAuthError(code, message, field string) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Field:   field,
	}
}

// AuthErrorHandler is called when authentication errors occur. The handler
// receives the structured error and should write the response. Returns true
// if the error was handled (response written), false to use the default JSON
// response.
//
// Example implementations:
//   - Redirect back to form with flash message (app uses their session library)
//   - Redirect with error in query params: /signup?error=email_exists
//   - Return JSON error response
//   - Log and show generic error page
type AuthErrorHandler func(err *AuthError, w http.ResponseWriter, r *http.Request) bool

// CredentialsValidator validates a username/password against the host's user
// store and returns the corresponding account. Used by both localauth's
// password login (NewCredentialsValidator returns this shape) and apiauth's
// password-grant token endpoint.
type CredentialsValidator func(username, password, usernameType string) (User, error)
