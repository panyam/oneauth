package oneauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// HandleSignup processes user registration
func (a *LocalAuth) HandleSignup(w http.ResponseWriter, r *http.Request) {
	if a.CreateUser == nil {
		http.Error(w, `{"error": "Signup not configured"}`, http.StatusInternalServerError)
		return
	}

	// Parse signup form data
	creds, err := a.parseSignupForm(r)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Validate signup credentials
	validator := a.ValidateSignup
	if validator == nil {
		validator = DefaultSignupValidator
	}
	if err := validator(creds); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Create the user
	user, err := a.CreateUser(creds)
	if err != nil {
		log.Println("error creating user: ", err)
		http.Error(w, fmt.Sprintf(`{"error": "Failed to create user: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Send verification email if configured
	var primaryEmail string
	if creds.Email != nil {
		primaryEmail = *creds.Email
	}

	if primaryEmail != "" && a.EmailSender != nil && a.TokenStore != nil && a.BaseURL != "" {
		token, err := a.TokenStore.CreateToken(user.Id(), primaryEmail, TokenTypeEmailVerification, TokenExpiryEmailVerification)
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
		userInfo := map[string]any{
			"username": creds.Username,
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

func (a *LocalAuth) parseSignupForm(r *http.Request) (*Credentials, error) {
	contentType := r.Header.Get("Content-Type")
	usernameField := a.getUsernameField()
	emailField := a.getEmailField()
	phoneField := a.getPhoneField()
	passwordField := a.getPasswordField()

	var username, email, phone, password string

	if contentType == "application/x-www-form-urlencoded" {
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("error parsing form")
		}
		username = r.FormValue(usernameField)
		email = r.FormValue(emailField)
		phone = r.FormValue(phoneField)
		password = r.FormValue(passwordField)
	} else {
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil || data == nil {
			return nil, fmt.Errorf("invalid post body")
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

	if username == "" {
		return nil, fmt.Errorf("username required")
	}
	if password == "" {
		return nil, fmt.Errorf("password required")
	}

	creds := &Credentials{
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
