package oneauth

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// =============================================================================
// SignupPolicy - Configurable signup requirements
// =============================================================================

// SignupPolicy defines what is required for signup
type SignupPolicy struct {
	RequireUsername       bool   // Is username required? (default: false)
	RequireEmail          bool   // Is email required? (default: true)
	RequirePhone          bool   // Is phone required? (default: false)
	RequirePassword       bool   // Is password required for local? (default: true)
	EnforceUsernameUnique bool   // Check UsernameStore? (default: true if username required)
	EnforceEmailUnique    bool   // Check IdentityStore? (default: true)
	MinPasswordLength     int    // Minimum password (default: 8)
	UsernamePattern       string // Regex for username (default: ^[a-zA-Z0-9_-]{3,20}$)
}

// DefaultSignupPolicy returns a sensible default signup policy
func DefaultSignupPolicy() SignupPolicy {
	return SignupPolicy{
		RequireUsername:       false,
		RequireEmail:          true,
		RequirePhone:          false,
		RequirePassword:       true,
		EnforceUsernameUnique: true,
		EnforceEmailUnique:    true,
		MinPasswordLength:     8,
		UsernamePattern:       `^[a-zA-Z0-9_-]{3,20}$`,
	}
}

// Preset policies for common use cases

// PolicyUsernameRequired requires username, email, and password for signup
var PolicyUsernameRequired = SignupPolicy{
	RequireUsername:       true,
	RequireEmail:          true,
	RequirePhone:          false,
	RequirePassword:       true,
	EnforceUsernameUnique: true,
	EnforceEmailUnique:    true,
	MinPasswordLength:     8,
	UsernamePattern:       `^[a-zA-Z0-9_-]{3,20}$`,
}

// PolicyEmailOnly requires only email and password for signup (username optional)
var PolicyEmailOnly = SignupPolicy{
	RequireUsername:       false,
	RequireEmail:          true,
	RequirePhone:          false,
	RequirePassword:       true,
	EnforceUsernameUnique: true,
	EnforceEmailUnique:    true,
	MinPasswordLength:     8,
	UsernamePattern:       `^[a-zA-Z0-9_-]{3,20}$`,
}

// PolicyFlexible is OAuth-friendly - email/phone optional, username optional
var PolicyFlexible = SignupPolicy{
	RequireUsername:       false,
	RequireEmail:          false,
	RequirePhone:          false,
	RequirePassword:       false,
	EnforceUsernameUnique: true,
	EnforceEmailUnique:    true,
	MinPasswordLength:     8,
	UsernamePattern:       `^[a-zA-Z0-9_-]{3,20}$`,
}

// GetUsernamePattern returns the compiled username regex pattern
func (p SignupPolicy) GetUsernamePattern() *regexp.Regexp {
	pattern := p.UsernamePattern
	if pattern == "" {
		pattern = `^[a-zA-Z0-9_-]{3,20}$`
	}
	return regexp.MustCompile(pattern)
}

// GetMinPasswordLength returns the minimum password length
func (p SignupPolicy) GetMinPasswordLength() int {
	if p.MinPasswordLength <= 0 {
		return 8
	}
	return p.MinPasswordLength
}

// =============================================================================
// AuthError - Structured authentication errors
// =============================================================================

// AuthError represents a structured authentication error
type AuthError struct {
	Code    string // "email_exists", "username_taken", "weak_password", "invalid_format", etc.
	Message string // Human-readable message
	Field   string // Which form field has the error (e.g., "email", "username", "password")
}

func (e *AuthError) Error() string {
	return e.Message
}

// Common error codes
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

// NewAuthError creates a new AuthError
func NewAuthError(code, message, field string) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Field:   field,
	}
}

// =============================================================================
// Error Handlers
// =============================================================================

// AuthErrorHandler is called when authentication errors occur.
// The handler receives the structured error and should write the response.
// Returns true if the error was handled (response written), false to use default JSON response.
//
// Example implementations:
//   - Redirect back to form with flash message (app uses their session library)
//   - Redirect with error in query params: /signup?error=email_exists
//   - Return JSON error response
//   - Log and show generic error page
type AuthErrorHandler func(err *AuthError, w http.ResponseWriter, r *http.Request) bool

// Credentials represents user credentials for signup or login
type Credentials struct {
	Username string  // Required for signup, can be username/email/phone for login
	Email    *string // Optional for signup
	Phone    *string // Optional for signup
	Password string  // Required
}

// SignupValidator validates credentials during signup
type SignupValidator func(creds *Credentials) error

// CredentialsValidator validates credentials during login and returns the user
type CredentialsValidator func(username, password, usernameType string) (User, error)

// CreateUserFunc creates a new user with the given credentials
type CreateUserFunc func(creds *Credentials) (User, error)

// DefaultSignupValidator provides sensible default validation for signup
var DefaultSignupValidator SignupValidator = func(creds *Credentials) error {
	// Username: 3-20 chars, alphanumeric + underscore + hyphen
	if len(creds.Username) < 3 || len(creds.Username) > 20 {
		return fmt.Errorf("username must be 3-20 characters")
	}
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !usernameRegex.MatchString(creds.Username) {
		return fmt.Errorf("username can only contain letters, numbers, underscores, and hyphens")
	}

	// At least one of email or phone required
	if creds.Email == nil && creds.Phone == nil {
		return fmt.Errorf("email or phone required")
	}

	// Email format check if provided
	if creds.Email != nil && *creds.Email != "" {
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(*creds.Email) {
			return fmt.Errorf("invalid email format")
		}
	}

	// Phone format check if provided (basic check - apps can customize)
	if creds.Phone != nil && *creds.Phone != "" {
		cleaned := strings.ReplaceAll(*creds.Phone, "-", "")
		cleaned = strings.ReplaceAll(cleaned, " ", "")
		cleaned = strings.ReplaceAll(cleaned, "(", "")
		cleaned = strings.ReplaceAll(cleaned, ")", "")
		if len(cleaned) < 10 {
			return fmt.Errorf("invalid phone number")
		}
	}

	// Password: minimum 8 characters
	if len(creds.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	return nil
}

// DetectUsernameType attempts to detect what type of username was provided
func DetectUsernameType(username string) string {
	if strings.Contains(username, "@") {
		return "email"
	}
	// Check if it looks like a phone number (starts with + or digit)
	if len(username) > 0 && (username[0] == '+' || (username[0] >= '0' && username[0] <= '9')) {
		return "phone"
	}
	return "username"
}
