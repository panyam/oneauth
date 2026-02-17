package oneauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/stores/fs"
	"golang.org/x/oauth2"
)

// testAuthService wraps the stores for testing
type testAuthService struct {
	UserStore     oa.UserStore
	IdentityStore oa.IdentityStore
	ChannelStore  oa.ChannelStore
	TokenStore    oa.TokenStore
}

// setupTestAuth creates a temporary storage directory and returns test services
func setupTestAuth(t *testing.T) (*testAuthService, string) {
	// Create temporary directory for test storage
	tmpDir, err := os.MkdirTemp("", "oneauth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	service := &testAuthService{
		UserStore:     fs.NewFSUserStore(tmpDir),
		IdentityStore: fs.NewFSIdentityStore(tmpDir),
		ChannelStore:  fs.NewFSChannelStore(tmpDir),
		TokenStore:    fs.NewFSTokenStore(tmpDir),
	}

	return service, tmpDir
}

// cleanup removes the temporary storage directory
func cleanup(t *testing.T, tmpDir string) {
	if err := os.RemoveAll(tmpDir); err != nil {
		t.Logf("Warning: failed to cleanup temp dir: %v", err)
	}
}

// TestSignupFlow tests user registration
func TestSignupFlow(t *testing.T) {
	service, tmpDir := setupTestAuth(t)
	defer cleanup(t, tmpDir)

	createUser := oa.NewCreateUserFunc(service.UserStore, service.IdentityStore, service.ChannelStore)
	localAuth := &oa.LocalAuth{
		CreateUser:  createUser,
		EmailSender: &oa.ConsoleEmailSender{},
		TokenStore:  service.TokenStore,
		BaseURL:     "http://localhost:8080",
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "user": userInfo})
		},
	}

	tests := []struct {
		name           string
		formData       map[string]string
		expectedStatus int
		checkError     string
	}{
		{
			name: "successful signup",
			formData: map[string]string{
				"username": "testuser",
				"email":    "test@example.com",
				"password": "password123",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "duplicate email",
			formData: map[string]string{
				"username": "testuser2",
				"email":    "test@example.com",
				"password": "password123",
			},
			expectedStatus: http.StatusBadRequest,
			checkError:     "already registered",
		},
		{
			name: "weak password",
			formData: map[string]string{
				"username": "testuser3",
				"email":    "test3@example.com",
				"password": "pass",
			},
			expectedStatus: http.StatusBadRequest,
			checkError:     "at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			for k, v := range tt.formData {
				form.Set(k, v)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			localAuth.HandleSignup(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.checkError != "" && !strings.Contains(rr.Body.String(), tt.checkError) {
				t.Errorf("Expected error containing %q, got: %s", tt.checkError, rr.Body.String())
			}
		})
	}
}

// TestLoginFlow tests user authentication
func TestLoginFlow(t *testing.T) {
	service, tmpDir := setupTestAuth(t)
	defer cleanup(t, tmpDir)

	createUser := oa.NewCreateUserFunc(service.UserStore, service.IdentityStore, service.ChannelStore)
	validateCreds := oa.NewCredentialsValidator(service.IdentityStore, service.ChannelStore, service.UserStore)

	localAuth := &oa.LocalAuth{
		CreateUser:          createUser,
		ValidateCredentials: validateCreds,
		UsernameField:       "email", // Accept email as username for login
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "user": userInfo})
		},
	}

	// Create test user
	testEmail := "login@example.com"
	testPassword := "password123"
	creds := &oa.Credentials{
		Username: "loginuser",
		Email:    &testEmail,
		Password: testPassword,
	}
	_, err := createUser(creds)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name           string
		email          string
		password       string
		expectedStatus int
	}{
		{
			name:           "successful login",
			email:          testEmail,
			password:       testPassword,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "wrong password",
			email:          testEmail,
			password:       "wrongpassword",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "non-existent user",
			email:          "nonexistent@example.com",
			password:       testPassword,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("email", tt.email)
			form.Set("password", tt.password)

			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			localAuth.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			// For successful login, verify userInfo contains email
			if tt.expectedStatus == http.StatusOK {
				var response map[string]any
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				user, ok := response["user"].(map[string]any)
				if !ok {
					t.Fatal("Response missing 'user' field")
				}

				// Verify email is present in userInfo
				email, hasEmail := user["email"].(string)
				if !hasEmail {
					t.Error("userInfo missing 'email' field - this will cause 'no valid identity found' error")
				}
				if email != tt.email {
					t.Errorf("Expected email %q in userInfo, got %q", tt.email, email)
				}

				// Verify username is also present
				if _, hasUsername := user["username"]; !hasUsername {
					t.Error("userInfo missing 'username' field")
				}
			}
		})
	}
}

// TestTokenExpiry verifies expired tokens are rejected
func TestTokenExpiry(t *testing.T) {
	service, tmpDir := setupTestAuth(t)
	defer cleanup(t, tmpDir)

	// Create an expired token
	token, err := service.TokenStore.CreateToken("testuser", "test@example.com", oa.TokenTypeEmailVerification, -1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Try to get the token - should fail
	_, err = service.TokenStore.GetToken(token.Token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Expected 'expired' error, got: %v", err)
	}
}

// TestUsernameDetection tests username type auto-detection
func TestUsernameDetection(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test@example.com", "email"},
		{"user@domain.co.uk", "email"},
		{"+1234567890", "phone"},
		{"1234567890", "phone"},
		{"username123", "username"},
		{"user_name", "username"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := oa.DetectUsernameType(tt.input)
			if result != tt.expected {
				t.Errorf("For input %q, expected %q, got %q", tt.input, tt.expected, result)
			}
		})
	}
}

// TestDefaultValidator tests the default signup validator
func TestDefaultValidator(t *testing.T) {
	tests := []struct {
		name      string
		creds     *oa.Credentials
		expectErr bool
		errText   string
	}{
		{
			name: "valid credentials",
			creds: &oa.Credentials{
				Username: "testuser",
				Email:    ptrString("test@example.com"),
				Password: "password123",
			},
			expectErr: false,
		},
		{
			name: "username too short",
			creds: &oa.Credentials{
				Username: "ab",
				Email:    ptrString("test@example.com"),
				Password: "password123",
			},
			expectErr: true,
			errText:   "username",
		},
		{
			name: "invalid email",
			creds: &oa.Credentials{
				Username: "testuser",
				Email:    ptrString("invalid-email"),
				Password: "password123",
			},
			expectErr: true,
			errText:   "email",
		},
		{
			name: "password too short",
			creds: &oa.Credentials{
				Username: "testuser",
				Email:    ptrString("test@example.com"),
				Password: "pass",
			},
			expectErr: true,
			errText:   "at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := oa.DefaultSignupValidator(tt.creds)
			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if tt.errText != "" && !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("Expected error containing %q, got: %v", tt.errText, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

// trackingEmailSender records sent emails for test assertions
type trackingEmailSender struct {
	verificationEmails []sentEmail
	resetEmails        []sentEmail
}

type sentEmail struct {
	to   string
	link string
}

func (t *trackingEmailSender) SendVerificationEmail(to, link string) error {
	t.verificationEmails = append(t.verificationEmails, sentEmail{to, link})
	return nil
}

func (t *trackingEmailSender) SendPasswordResetEmail(to, link string) error {
	t.resetEmails = append(t.resetEmails, sentEmail{to, link})
	return nil
}

// setupPasswordResetAuth creates a LocalAuth configured for password reset testing
func setupPasswordResetAuth(t *testing.T) (*oa.LocalAuth, *testAuthService, *trackingEmailSender, string) {
	service, tmpDir := setupTestAuth(t)

	createUser := oa.NewCreateUserFunc(service.UserStore, service.IdentityStore, service.ChannelStore)
	updatePassword := oa.NewUpdatePasswordFunc(service.IdentityStore, service.ChannelStore)
	emailSender := &trackingEmailSender{}

	localAuth := &oa.LocalAuth{
		CreateUser:     createUser,
		EmailSender:    emailSender,
		TokenStore:     service.TokenStore,
		BaseURL:        "http://localhost:8080",
		UpdatePassword: updatePassword,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "user": userInfo})
		},
	}

	// Create a test user
	testEmail := "reset@example.com"
	creds := &oa.Credentials{
		Username: "resetuser",
		Email:    &testEmail,
		Password: "oldpassword123",
	}
	_, err := createUser(creds)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	return localAuth, service, emailSender, tmpDir
}

// TestForgotPasswordForm tests GET /auth/forgot-password
func TestForgotPasswordForm(t *testing.T) {
	t.Run("json mode renders basic HTML form", func(t *testing.T) {
		localAuth, _, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		req := httptest.NewRequest(http.MethodGet, "/auth/forgot-password", nil)
		rr := httptest.NewRecorder()

		localAuth.HandleForgotPasswordForm(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "<form") {
			t.Error("Expected HTML form in response")
		}
		if !strings.Contains(body, "forgot-password") {
			t.Error("Expected form to post to forgot-password")
		}
	})

	t.Run("redirect mode redirects to ForgotPasswordURL", func(t *testing.T) {
		localAuth, _, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		localAuth.ForgotPasswordURL = "/forgot-password"

		req := httptest.NewRequest(http.MethodGet, "/auth/forgot-password", nil)
		rr := httptest.NewRecorder()

		localAuth.HandleForgotPasswordForm(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", rr.Code)
		}
		location := rr.Header().Get("Location")
		if location != "/forgot-password" {
			t.Errorf("Expected redirect to /forgot-password, got %q", location)
		}
	})
}

// TestForgotPassword tests POST /auth/forgot-password
func TestForgotPassword(t *testing.T) {
	t.Run("json mode returns success JSON", func(t *testing.T) {
		localAuth, _, emailSender, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		form := url.Values{}
		form.Set("email", "reset@example.com")

		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleForgotPassword(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var response map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if response["success"] != true {
			t.Error("Expected success: true")
		}

		if len(emailSender.resetEmails) != 1 {
			t.Fatalf("Expected 1 reset email sent, got %d", len(emailSender.resetEmails))
		}
		if emailSender.resetEmails[0].to != "reset@example.com" {
			t.Errorf("Expected email to reset@example.com, got %s", emailSender.resetEmails[0].to)
		}
	})

	t.Run("redirect mode redirects with sent=true", func(t *testing.T) {
		localAuth, _, emailSender, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		localAuth.ForgotPasswordURL = "/forgot-password"

		form := url.Values{}
		form.Set("email", "reset@example.com")

		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleForgotPassword(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Errorf("Expected status 303, got %d", rr.Code)
		}
		location := rr.Header().Get("Location")
		if location != "/forgot-password?sent=true" {
			t.Errorf("Expected redirect to /forgot-password?sent=true, got %q", location)
		}

		if len(emailSender.resetEmails) != 1 {
			t.Fatalf("Expected 1 reset email sent, got %d", len(emailSender.resetEmails))
		}
	})

	t.Run("missing email returns error", func(t *testing.T) {
		localAuth, _, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		form := url.Values{}
		// no email set

		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleForgotPassword(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d. Body: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("nonexistent email still returns success (no enumeration)", func(t *testing.T) {
		localAuth, _, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		form := url.Values{}
		form.Set("email", "nonexistent@example.com")

		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleForgotPassword(rr, req)

		// Should still return success to prevent email enumeration
		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}
	})
}

// TestResetPasswordForm tests GET /auth/reset-password
func TestResetPasswordForm(t *testing.T) {
	t.Run("json mode renders basic HTML form with token", func(t *testing.T) {
		localAuth, service, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		token, err := service.TokenStore.CreateToken("", "reset@example.com", oa.TokenTypePasswordReset, oa.TokenExpiryPasswordReset)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/auth/reset-password?token="+token.Token, nil)
		rr := httptest.NewRecorder()

		localAuth.HandleResetPasswordForm(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "<form") {
			t.Error("Expected HTML form in response")
		}
		if !strings.Contains(body, token.Token) {
			t.Error("Expected token in hidden field")
		}
	})

	t.Run("json mode rejects missing token", func(t *testing.T) {
		localAuth, _, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		req := httptest.NewRequest(http.MethodGet, "/auth/reset-password", nil)
		rr := httptest.NewRecorder()

		localAuth.HandleResetPasswordForm(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})

	t.Run("redirect mode redirects to ResetPasswordURL with token", func(t *testing.T) {
		localAuth, service, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		localAuth.ResetPasswordURL = "/reset-password"

		token, err := service.TokenStore.CreateToken("", "reset@example.com", oa.TokenTypePasswordReset, oa.TokenExpiryPasswordReset)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/auth/reset-password?token="+token.Token, nil)
		rr := httptest.NewRecorder()

		localAuth.HandleResetPasswordForm(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", rr.Code)
		}
		location := rr.Header().Get("Location")
		expected := "/reset-password?token=" + token.Token
		if location != expected {
			t.Errorf("Expected redirect to %q, got %q", expected, location)
		}
	})

	t.Run("redirect mode redirects without token when missing", func(t *testing.T) {
		localAuth, _, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		localAuth.ResetPasswordURL = "/reset-password"

		req := httptest.NewRequest(http.MethodGet, "/auth/reset-password", nil)
		rr := httptest.NewRecorder()

		localAuth.HandleResetPasswordForm(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", rr.Code)
		}
		location := rr.Header().Get("Location")
		if location != "/reset-password" {
			t.Errorf("Expected redirect to /reset-password, got %q", location)
		}
	})
}

// TestResetPassword tests POST /auth/reset-password
func TestResetPassword(t *testing.T) {
	t.Run("json mode resets password and returns success", func(t *testing.T) {
		localAuth, service, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		// Create a valid reset token
		token, err := service.TokenStore.CreateToken("", "reset@example.com", oa.TokenTypePasswordReset, oa.TokenExpiryPasswordReset)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		form := url.Values{}
		form.Set("token", token.Token)
		form.Set("password", "newpassword123")

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var response map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if response["success"] != true {
			t.Error("Expected success: true")
		}

		// Token should be deleted after use
		_, err = service.TokenStore.GetToken(token.Token)
		if err == nil {
			t.Error("Expected token to be deleted after use")
		}
	})

	t.Run("redirect mode redirects with success=true", func(t *testing.T) {
		localAuth, service, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		localAuth.ResetPasswordURL = "/reset-password"

		token, err := service.TokenStore.CreateToken("", "reset@example.com", oa.TokenTypePasswordReset, oa.TokenExpiryPasswordReset)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		form := url.Values{}
		form.Set("token", token.Token)
		form.Set("password", "newpassword123")

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Errorf("Expected status 303, got %d. Body: %s", rr.Code, rr.Body.String())
		}
		location := rr.Header().Get("Location")
		if location != "/reset-password?success=true" {
			t.Errorf("Expected redirect to /reset-password?success=true, got %q", location)
		}
	})

	t.Run("redirect mode redirects with error on invalid token", func(t *testing.T) {
		localAuth, _, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		localAuth.ResetPasswordURL = "/reset-password"

		form := url.Values{}
		form.Set("token", "invalid-token-value")
		form.Set("password", "newpassword123")

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Errorf("Expected status 303, got %d", rr.Code)
		}
		location := rr.Header().Get("Location")
		if !strings.Contains(location, "error=") {
			t.Errorf("Expected redirect with error param, got %q", location)
		}
	})

	t.Run("short password returns error", func(t *testing.T) {
		localAuth, service, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		token, err := service.TokenStore.CreateToken("", "reset@example.com", oa.TokenTypePasswordReset, oa.TokenExpiryPasswordReset)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		form := url.Values{}
		form.Set("token", token.Token)
		form.Set("password", "short")

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "at least 8 characters") {
			t.Errorf("Expected password length error, got: %s", rr.Body.String())
		}
	})

	t.Run("missing token and password returns error", func(t *testing.T) {
		localAuth, _, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		form := url.Values{}
		// empty form

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})

	t.Run("expired token returns error", func(t *testing.T) {
		localAuth, service, _, tmpDir := setupPasswordResetAuth(t)
		defer cleanup(t, tmpDir)

		// Create an expired token
		token, err := service.TokenStore.CreateToken("", "reset@example.com", oa.TokenTypePasswordReset, -1*time.Hour)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		form := url.Values{}
		form.Set("token", token.Token)
		form.Set("password", "newpassword123")

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		// Should fail because token is expired
		if rr.Code == http.StatusOK {
			t.Error("Expected error for expired token, but got 200")
		}
	})
}

// TestForgotPasswordEndToEnd tests the full forgot → reset flow
func TestForgotPasswordEndToEnd(t *testing.T) {
	localAuth, service, emailSender, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)

	validateCreds := oa.NewCredentialsValidator(service.IdentityStore, service.ChannelStore, service.UserStore)
	localAuth.ValidateCredentials = validateCreds

	// Step 1: Request password reset
	form := url.Values{}
	form.Set("email", "reset@example.com")

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	localAuth.HandleForgotPassword(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Forgot password failed: status %d, body: %s", rr.Code, rr.Body.String())
	}

	// Verify email was sent with reset link
	if len(emailSender.resetEmails) != 1 {
		t.Fatalf("Expected 1 reset email, got %d", len(emailSender.resetEmails))
	}
	resetLink := emailSender.resetEmails[0].link
	if !strings.Contains(resetLink, "token=") {
		t.Fatalf("Reset link missing token: %s", resetLink)
	}

	// Extract token from the link
	u, err := url.Parse(resetLink)
	if err != nil {
		t.Fatalf("Failed to parse reset link: %v", err)
	}
	resetToken := u.Query().Get("token")

	// Step 2: Reset password using the token
	newPassword := "brandnewpassword"
	form2 := url.Values{}
	form2.Set("token", resetToken)
	form2.Set("password", newPassword)

	req2 := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()

	localAuth.HandleResetPassword(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("Reset password failed: status %d, body: %s", rr2.Code, rr2.Body.String())
	}

	// Step 3: Verify old password no longer works
	_, err = validateCreds("reset@example.com", "oldpassword123", "email")
	if err == nil {
		t.Error("Old password should no longer work")
	}

	// Step 4: Verify new password works
	user, err := validateCreds("reset@example.com", newPassword, "email")
	if err != nil {
		t.Fatalf("New password should work, got error: %v", err)
	}
	if user == nil {
		t.Fatal("Expected user from credential validation")
	}
}

func ptrString(s string) *string {
	return &s
}
