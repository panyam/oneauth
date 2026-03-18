package localauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/panyam/oneauth/core"
)

// HandleSignup processes user registration
func (a *LocalAuth) HandleSignup(w http.ResponseWriter, r *http.Request) {
	if a.CreateUser == nil {
		http.Error(w, `{"error": "Signup not configured"}`, http.StatusInternalServerError)
		return
	}

	// Parse signup form data
	creds, parseErr := a.parseSignupForm(r)
	if parseErr != nil {
		a.handleSignupError(parseErr, w, r)
		return
	}

	// Validate signup credentials using policy or legacy validator
	if authErr := a.validateSignupCredentials(creds); authErr != nil {
		a.handleSignupError(authErr, w, r)
		return
	}

	// Check username uniqueness if configured
	if creds.Username != "" && a.UsernameStore != nil {
		policy := a.getSignupPolicy()
		if policy.EnforceUsernameUnique {
			if _, err := a.UsernameStore.GetUserByUsername(creds.Username); err == nil {
				authErr := core.NewAuthError(core.ErrCodeUsernameTaken, "Username is already taken", "username")
				a.handleSignupError(authErr, w, r)
				return
			}
		}
	}

	// Create the user
	user, err := a.CreateUser(creds)
	if err != nil {
		log.Println("error creating user: ", err)
		// Try to detect specific error types
		errMsg := err.Error()
		if strings.Contains(errMsg, "already registered") || strings.Contains(errMsg, "already exists") {
			authErr := core.NewAuthError(core.ErrCodeEmailExists, errMsg, "email")
			a.handleSignupError(authErr, w, r)
		} else {
			authErr := core.NewAuthError("create_failed", fmt.Sprintf("Failed to create user: %s", errMsg), "")
			a.handleSignupError(authErr, w, r)
		}
		return
	}

	// Reserve username if UsernameStore is configured
	if creds.Username != "" && a.UsernameStore != nil {
		if err := a.UsernameStore.ReserveUsername(creds.Username, user.Id()); err != nil {
			log.Printf("Warning: failed to reserve username %s: %v", creds.Username, err)
			// Don't fail signup - user was already created
		}
	}

	// Send verification email if configured
	var primaryEmail string
	if creds.Email != nil {
		primaryEmail = *creds.Email
	}

	if primaryEmail != "" && a.EmailSender != nil && a.TokenStore != nil && a.BaseURL != "" {
		token, err := a.TokenStore.CreateToken(user.Id(), primaryEmail, core.TokenTypeEmailVerification, core.TokenExpiryEmailVerification)
		if err != nil {
			log.Println("error creating verification token: ", err)
		} else {
			verificationLink := fmt.Sprintf("%s/auth/verify-email?token=%s", a.BaseURL, token.Token)
			if err := a.EmailSender.SendVerificationEmail(primaryEmail, verificationLink); err != nil {
				log.Println("error sending verification email: ", err)
			}
		}
	}

	// Log user in automatically (unless email verification is required)
	if !a.RequireEmailVerification || a.EmailSender == nil {
		// Note: token is nil for local auth (no OAuth tokens)
		userInfo := map[string]any{}
		if creds.Username != "" {
			userInfo["username"] = creds.Username
		}
		if creds.Email != nil {
			userInfo["email"] = *creds.Email
		}
		if creds.Phone != nil {
			userInfo["phone"] = *creds.Phone
		}
		a.HandleUser("local", a.getProvider(), nil, userInfo, w, r)
	} else {
		// User created but needs to verify email
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message": "User created. Please check your email to verify your account.", "user_id": "%s"}`, user.Id())
	}
}

// getSignupPolicy returns the configured policy or default
func (a *LocalAuth) getSignupPolicy() core.SignupPolicy {
	if a.SignupPolicy != nil {
		return *a.SignupPolicy
	}
	return core.DefaultSignupPolicy()
}

// validateSignupCredentials validates credentials using policy or legacy validator
func (a *LocalAuth) validateSignupCredentials(creds *core.Credentials) *core.AuthError {
	// If SignupPolicy is set, use policy-based validation
	if a.SignupPolicy != nil {
		return a.validateWithPolicy(creds, *a.SignupPolicy)
	}

	// Otherwise, use legacy validator for backwards compatibility
	validator := a.ValidateSignup
	if validator == nil {
		validator = core.DefaultSignupValidator
	}
	if err := validator(creds); err != nil {
		// Convert to AuthError (best effort to detect field)
		errMsg := err.Error()
		field := ""
		code := "validation_error"
		if strings.Contains(errMsg, "username") {
			field = "username"
			code = core.ErrCodeInvalidUsername
		} else if strings.Contains(errMsg, "email") {
			field = "email"
			code = core.ErrCodeInvalidEmail
		} else if strings.Contains(errMsg, "phone") {
			field = "phone"
			code = core.ErrCodeInvalidPhone
		} else if strings.Contains(errMsg, "password") {
			field = "password"
			code = core.ErrCodeWeakPassword
		}
		return core.NewAuthError(code, errMsg, field)
	}
	return nil
}

// validateWithPolicy validates credentials against the signup policy
func (a *LocalAuth) validateWithPolicy(creds *core.Credentials, policy core.SignupPolicy) *core.AuthError {
	// Check required fields
	if policy.RequireUsername && creds.Username == "" {
		return core.NewAuthError(core.ErrCodeMissingField, "Username is required", "username")
	}
	if policy.RequireEmail && (creds.Email == nil || *creds.Email == "") {
		return core.NewAuthError(core.ErrCodeMissingField, "Email is required", "email")
	}
	if policy.RequirePhone && (creds.Phone == nil || *creds.Phone == "") {
		return core.NewAuthError(core.ErrCodeMissingField, "Phone is required", "phone")
	}
	if policy.RequirePassword && creds.Password == "" {
		return core.NewAuthError(core.ErrCodeMissingField, "Password is required", "password")
	}

	// Validate username format if provided
	if creds.Username != "" {
		pattern := policy.GetUsernamePattern()
		if !pattern.MatchString(creds.Username) {
			return core.NewAuthError(core.ErrCodeInvalidUsername, "Username must be 3-20 characters and contain only letters, numbers, underscores, and hyphens", "username")
		}
	}

	// Validate email format if provided
	if creds.Email != nil && *creds.Email != "" {
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(*creds.Email) {
			return core.NewAuthError(core.ErrCodeInvalidEmail, "Invalid email format", "email")
		}
	}

	// Validate phone format if provided (basic check)
	if creds.Phone != nil && *creds.Phone != "" {
		cleaned := strings.ReplaceAll(*creds.Phone, "-", "")
		cleaned = strings.ReplaceAll(cleaned, " ", "")
		cleaned = strings.ReplaceAll(cleaned, "(", "")
		cleaned = strings.ReplaceAll(cleaned, ")", "")
		if len(cleaned) < 10 {
			return core.NewAuthError(core.ErrCodeInvalidPhone, "Invalid phone number", "phone")
		}
	}

	// Validate password strength
	if creds.Password != "" {
		minLen := policy.GetMinPasswordLength()
		if len(creds.Password) < minLen {
			return core.NewAuthError(core.ErrCodeWeakPassword, fmt.Sprintf("Password must be at least %d characters", minLen), "password")
		}
	}

	return nil
}

// parseSignupForm parses signup form data without validation
func (a *LocalAuth) parseSignupForm(r *http.Request) (*core.Credentials, *core.AuthError) {
	contentType := r.Header.Get("Content-Type")
	// For signup, always use "username" field (UsernameField is for login only)
	usernameField := "username"
	emailField := a.getEmailField()
	phoneField := a.getPhoneField()
	passwordField := a.getPasswordField()

	var username, email, phone, password string

	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseForm(); err != nil {
			return nil, core.NewAuthError("parse_error", "Error parsing form", "")
		}
		username = r.FormValue(usernameField)
		email = r.FormValue(emailField)
		phone = r.FormValue(phoneField)
		password = r.FormValue(passwordField)
	} else {
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil || data == nil {
			return nil, core.NewAuthError("parse_error", "Invalid post body", "")
		}
		if u, ok := data[usernameField].(string); ok {
			username = u
		}
		if e, ok := data[emailField].(string); ok {
			email = e
		}
		if p, ok := data[phoneField].(string); ok {
			phone = p
		}
		if pw, ok := data[passwordField].(string); ok {
			password = pw
		}
	}

	creds := &core.Credentials{
		Username: username,
		Password: password,
	}

	if email != "" {
		creds.Email = &email
	}
	if phone != "" {
		creds.Phone = &phone
	}

	return creds, nil
}
