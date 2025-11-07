package oneauth

import (
	"fmt"
	"regexp"
	"strings"
)

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
