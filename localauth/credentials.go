package localauth

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/panyam/oneauth/accounts"
)

// =============================================================================
// SignupPolicy — Configurable signup requirements
// =============================================================================

// SignupPolicy defines what is required for signup.
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

// DefaultSignupPolicy returns a sensible default signup policy.
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

// PolicyUsernameRequired requires username, email, and password for signup.
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

// PolicyEmailOnly requires only email and password for signup (username optional).
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

// PolicyFlexible is OAuth-friendly — email/phone optional, username optional.
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

// GetUsernamePattern returns the compiled username regex pattern.
func (p SignupPolicy) GetUsernamePattern() *regexp.Regexp {
	pattern := p.UsernamePattern
	if pattern == "" {
		pattern = `^[a-zA-Z0-9_-]{3,20}$`
	}
	return regexp.MustCompile(pattern)
}

// GetMinPasswordLength returns the minimum password length.
func (p SignupPolicy) GetMinPasswordLength() int {
	if p.MinPasswordLength <= 0 {
		return 8
	}
	return p.MinPasswordLength
}

// =============================================================================
// Credentials and validators
// =============================================================================

// Credentials represents user credentials for signup or login.
type Credentials struct {
	Username string  // Required for signup, can be username/email/phone for login
	Email    *string // Optional for signup
	Phone    *string // Optional for signup
	Password string  // Required
}

// SignupValidator validates credentials during signup.
type SignupValidator func(creds *Credentials) error

// CredentialsValidator is the same shape as accounts.CredentialsValidator —
// type-aliased here so existing localauth callers don't have to switch
// imports.
type CredentialsValidator = accounts.CredentialsValidator

// CreateUserFunc creates a new user with the given credentials.
type CreateUserFunc func(creds *Credentials) (accounts.User, error)

// DefaultSignupValidator provides sensible default validation for signup.
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

	// Phone format check if provided (basic check — apps can customize)
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

// DetectUsernameType is re-exported from accounts so callers that import
// localauth don't need a second import for this widely-used helper.
func DetectUsernameType(username string) string {
	return accounts.DetectUsernameType(username)
}
