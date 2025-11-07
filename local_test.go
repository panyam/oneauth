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
	"github.com/panyam/oneauth/stores"
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
		UserStore:     stores.NewFSUserStore(tmpDir),
		IdentityStore: stores.NewFSIdentityStore(tmpDir),
		ChannelStore:  stores.NewFSChannelStore(tmpDir),
		TokenStore:    stores.NewFSTokenStore(tmpDir),
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

func ptrString(s string) *string {
	return &s
}
