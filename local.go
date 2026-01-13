package oneauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type HandleUserFunc func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request)
type VerifyEmailFunc func(token string) error
type UpdatePasswordFunc func(email, newPassword string) error

// Allows local username/password based authentication
type LocalAuth struct {
	// Validates credentials during login
	ValidateCredentials CredentialsValidator

	// Validates credentials during signup
	ValidateSignup SignupValidator

	// Creates a new user (for signup)
	CreateUser CreateUserFunc

	// Optional email sender for verification emails
	EmailSender SendEmail

	// Optional token store for email verification and password reset
	TokenStore TokenStore

	// Base URL for generating verification/reset links
	BaseURL string

	// Whether email verification is required before login
	RequireEmailVerification bool

	// Provider name (defaults to "local")
	Provider string

	// Form field names
	UsernameField string
	PasswordField string
	EmailField    string
	PhoneField    string

	// Handler called after successful authentication
	HandleUser HandleUserFunc

	// Callback to verify email by token
	VerifyEmail VerifyEmailFunc

	// Callback to update password
	UpdatePassword UpdatePasswordFunc
}

// ServeHTTP handles login requests
func (a *LocalAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.ValidateCredentials == nil {
		http.Error(w, `{"error": "Login not configured"}`, http.StatusInternalServerError)
		return
	}

	// Parse form data
	username, password, err := a.parseLoginForm(r)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Detect username type (email, phone, or username) if not specified
	usernameType := DetectUsernameType(username)

	// Validate credentials
	user, err := a.ValidateCredentials(username, password, usernameType)
	if err != nil || user == nil {
		if err != nil {
			log.Println("error validating user: ", err)
		}
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// Create user info for HandleUser callback
	// Note: token is nil for local auth (no OAuth tokens)
	// Start with user's profile and add/override with username
	userInfo := user.Profile()
	if userInfo == nil {
		userInfo = make(map[string]any)
	}

	// Add username to userInfo
	userInfo["username"] = username

	// Ensure email or phone is in userInfo based on login type
	if usernameType == "email" && userInfo["email"] == nil {
		userInfo["email"] = username
	} else if usernameType == "phone" && userInfo["phone"] == nil {
		userInfo["phone"] = username
	}

	// Call the authentication success handler
	a.HandleUser("local", a.getProvider(), nil, userInfo, w, r)
}

func (a *LocalAuth) parseLoginForm(r *http.Request) (username, password string, err error) {
	contentType := r.Header.Get("Content-Type")
	usernameField := a.getUsernameField()
	passwordField := a.getPasswordField()

	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if err = r.ParseForm(); err != nil {
			return "", "", fmt.Errorf("error parsing form")
		}
		username = r.FormValue(usernameField)
		password = r.FormValue(passwordField)
	} else {
		var data map[string]any
		if err = json.NewDecoder(r.Body).Decode(&data); err != nil || data == nil {
			return "", "", fmt.Errorf("invalid post body")
		}
		if u, ok := data[usernameField].(string); ok {
			username = u
		}
		if p, ok := data[passwordField].(string); ok {
			password = p
		}
	}

	if username == "" || password == "" {
		return "", "", fmt.Errorf("username and password required")
	}

	return username, password, nil
}

func (a *LocalAuth) getProvider() string {
	if a.Provider != "" {
		return a.Provider
	}
	return "local"
}

func (a *LocalAuth) getUsernameField() string {
	if a.UsernameField != "" {
		return a.UsernameField
	}
	return "username" // default field name for username
}

func (a *LocalAuth) getPasswordField() string {
	if a.PasswordField != "" {
		return a.PasswordField
	}
	return "password"
}

func (a *LocalAuth) getEmailField() string {
	if a.EmailField != "" {
		return a.EmailField
	}
	return "email"
}

func (a *LocalAuth) getPhoneField() string {
	if a.PhoneField != "" {
		return a.PhoneField
	}
	return "phone"
}

// HandleVerifyEmail handles email verification via token
func (a *LocalAuth) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if a.VerifyEmail == nil {
		http.Error(w, `{"error": "Email verification not configured"}`, http.StatusInternalServerError)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, `{"error": "Token required"}`, http.StatusBadRequest)
		return
	}

	// Call the verification callback
	if err := a.VerifyEmail(token); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Redirect to success page or return JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Email verified successfully",
	})
}

// HandleForgotPasswordForm shows the forgot password form (GET)
func (a *LocalAuth) HandleForgotPasswordForm(w http.ResponseWriter, r *http.Request) {
	// This should render a template page
	// For now, return a simple message
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Forgot Password</title></head>
<body>
<h1>Forgot Password</h1>
<form method="POST" action="/auth/forgot-password">
	<label>Email: <input type="email" name="email" required></label>
	<button type="submit">Send Reset Link</button>
</form>
</body>
</html>`)
}

// HandleForgotPassword handles forgot password requests (POST)
func (a *LocalAuth) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if a.TokenStore == nil || a.EmailSender == nil {
		http.Error(w, `{"error": "Password reset not configured"}`, http.StatusInternalServerError)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Invalid form data"}`, http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, `{"error": "Email required"}`, http.StatusBadRequest)
		return
	}

	// Generate reset token
	// Note: We need UserID for CreateToken, but we don't want to reveal if email exists
	// For security, always return success even if email doesn't exist
	token, err := a.TokenStore.CreateToken("", email, TokenTypePasswordReset, TokenExpiryPasswordReset)
	if err != nil {
		log.Printf("Error creating reset token: %v", err)
		// Still return success to avoid revealing if email exists
	} else {
		// Send reset email
		resetLink := fmt.Sprintf("%s/auth/reset-password?token=%s", a.BaseURL, token.Token)
		if err := a.EmailSender.SendPasswordResetEmail(email, resetLink); err != nil {
			log.Printf("Error sending reset email: %v", err)
		}
	}

	// Always return success for security
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "If that email exists, a reset link has been sent",
	})
}

// HandleResetPasswordForm shows the reset password form (GET)
func (a *LocalAuth) HandleResetPasswordForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}

	// Verify token exists and is valid
	if a.TokenStore != nil {
		if _, err := a.TokenStore.GetToken(token); err != nil {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}
	}

	// Render form
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Reset Password</title></head>
<body>
<h1>Reset Password</h1>
<form method="POST" action="/auth/reset-password">
	<input type="hidden" name="token" value="%s">
	<label>New Password: <input type="password" name="password" required minlength="8"></label>
	<button type="submit">Reset Password</button>
</form>
</body>
</html>`, token)
}

// HandleResetPassword handles password reset submissions (POST)
func (a *LocalAuth) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if a.TokenStore == nil || a.UpdatePassword == nil {
		http.Error(w, `{"error": "Password reset not configured"}`, http.StatusInternalServerError)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Invalid form data"}`, http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	password := r.FormValue("password")

	if token == "" || password == "" {
		http.Error(w, `{"error": "Token and password required"}`, http.StatusBadRequest)
		return
	}

	// Validate token
	authToken, err := a.TokenStore.GetToken(token)
	if err != nil {
		http.Error(w, `{"error": "Invalid or expired token"}`, http.StatusBadRequest)
		return
	}

	if authToken.Type != TokenTypePasswordReset {
		http.Error(w, `{"error": "Invalid token type"}`, http.StatusBadRequest)
		return
	}

	// Password validation
	if len(password) < 8 {
		http.Error(w, `{"error": "Password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}

	// Update the password via callback
	if err := a.UpdatePassword(authToken.Email, password); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Delete the token (one-time use)
	if err := a.TokenStore.DeleteToken(token); err != nil {
		log.Printf("Warning: failed to delete token: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Password reset successfully",
		"email":   authToken.Email,
	})
}
