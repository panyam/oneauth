package oneauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/stores"
	"golang.org/x/oauth2"
)

// setupTestAuthComplete creates a fully configured LocalAuth for testing all flows
func setupTestAuthComplete(t *testing.T) (*oa.LocalAuth, *stores.FSUserStore, *stores.FSIdentityStore, *stores.FSChannelStore, *stores.FSTokenStore, string) {
	tmpDir, err := os.MkdirTemp("", "oneauth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	userStore := stores.NewFSUserStore(tmpDir)
	identityStore := stores.NewFSIdentityStore(tmpDir)
	channelStore := stores.NewFSChannelStore(tmpDir)
	tokenStore := stores.NewFSTokenStore(tmpDir)

	localAuth := &oa.LocalAuth{
		ValidateCredentials:      oa.NewCredentialsValidator(identityStore, channelStore, userStore),
		CreateUser:               oa.NewCreateUserFunc(userStore, identityStore, channelStore),
		ValidateSignup:           nil, // Use default validator
		EmailSender:              &oa.ConsoleEmailSender{},
		TokenStore:               tokenStore,
		BaseURL:                  "http://localhost:8080",
		RequireEmailVerification: false,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"user":    userInfo,
			})
		},
		VerifyEmail:    oa.NewVerifyEmailFunc(identityStore, tokenStore),
		UpdatePassword: oa.NewUpdatePasswordFunc(identityStore, channelStore),
	}

	return localAuth, userStore, identityStore, channelStore, tokenStore, tmpDir
}

func cleanupTest(t *testing.T, tmpDir string) {
	if err := os.RemoveAll(tmpDir); err != nil {
		t.Logf("Warning: failed to cleanup temp dir: %v", err)
	}
}

// TestCompleteSignupFlow tests the complete user signup flow
func TestCompleteSignupFlow(t *testing.T) {
	localAuth, userStore, identityStore, channelStore, _, tmpDir := setupTestAuthComplete(t)
	defer cleanupTest(t, tmpDir)

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
			name: "missing email",
			formData: map[string]string{
				"username": "testuser3",
				"password": "password123",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "weak password",
			formData: map[string]string{
				"username": "testuser4",
				"email":    "test4@example.com",
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

	// Verify user was created in storage
	t.Run("verify user in storage", func(t *testing.T) {
		identity, _, err := identityStore.GetIdentity("email", "test@example.com", false)
		if err != nil {
			t.Fatalf("Failed to get identity: %v", err)
		}
		if identity.UserID == "" {
			t.Error("Identity should have a user ID")
		}

		user, err := userStore.GetUserById(identity.UserID)
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}
		if user == nil {
			t.Error("User should exist")
		}

		// Verify channel exists
		identityKey := oa.IdentityKey("email", "test@example.com")
		channel, _, err := channelStore.GetChannel("local", identityKey, false)
		if err != nil {
			t.Fatalf("Failed to get channel: %v", err)
		}
		if channel.Credentials["password_hash"] == nil {
			t.Error("Channel should have password hash")
		}
	})
}

// TestCompleteLoginFlow tests the user login flow
func TestCompleteLoginFlow(t *testing.T) {
	localAuth, _, _, _, _, tmpDir := setupTestAuthComplete(t)
	defer cleanupTest(t, tmpDir)

	// Set UsernameField to "email" for login
	localAuth.UsernameField = "email"

	// Create a test user
	testEmail := "logintest@example.com"
	testPassword := "password123"
	creds := &oa.Credentials{
		Username: "loginuser",
		Email:    &testEmail,
		Password: testPassword,
	}
	_, err := localAuth.CreateUser(creds)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name           string
		email          string
		password       string
		expectedStatus int
		checkError     string
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
			checkError:     "Invalid credentials",
		},
		{
			name:           "non-existent user",
			email:          "nonexistent@example.com",
			password:       testPassword,
			expectedStatus: http.StatusUnauthorized,
			checkError:     "Invalid credentials",
		},
		{
			name:           "missing password",
			email:          testEmail,
			password:       "",
			expectedStatus: http.StatusBadRequest,
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

			if tt.checkError != "" && !strings.Contains(rr.Body.String(), tt.checkError) {
				t.Errorf("Expected error containing %q, got: %s", tt.checkError, rr.Body.String())
			}
		})
	}
}

// TestEmailVerificationFlow tests the email verification flow
func TestEmailVerificationFlow(t *testing.T) {
	localAuth, _, identityStore, _, tokenStore, tmpDir := setupTestAuthComplete(t)
	defer cleanupTest(t, tmpDir)

	testEmail := "verify@example.com"

	// Create a verification token
	token, err := tokenStore.CreateToken("testuser123", testEmail, oa.TokenTypeEmailVerification, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Create identity (unverified)
	identity := &oa.Identity{
		Type:     "email",
		Value:    testEmail,
		UserID:   "testuser123",
		Verified: false,
	}
	if err := identityStore.SaveIdentity(identity); err != nil {
		t.Fatalf("Failed to save identity: %v", err)
	}

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		checkSuccess   bool
	}{
		{
			name:           "successful verification",
			token:          token.Token,
			expectedStatus: http.StatusOK,
			checkSuccess:   true,
		},
		{
			name:           "missing token",
			token:          "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid token",
			token:          "invalid-token-12345",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "expired token (reuse attempt)",
			token:          token.Token,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+tt.token, nil)
			rr := httptest.NewRecorder()

			localAuth.HandleVerifyEmail(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.checkSuccess {
				var response map[string]any
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if response["success"] != true {
					t.Error("Expected success to be true")
				}

				// Verify identity is marked as verified
				verifiedIdentity, _, err := identityStore.GetIdentity("email", testEmail, false)
				if err != nil {
					t.Fatalf("Failed to get identity: %v", err)
				}
				if !verifiedIdentity.Verified {
					t.Error("Identity should be marked as verified")
				}
			}
		})
	}
}

// TestPasswordResetFlow tests the complete password reset flow
func TestPasswordResetFlow(t *testing.T) {
	localAuth, _, _, _, tokenStore, tmpDir := setupTestAuthComplete(t)
	defer cleanupTest(t, tmpDir)

	testEmail := "reset@example.com"
	oldPassword := "oldpassword123"
	newPassword := "newpassword456"

	// Create a user
	creds := &oa.Credentials{
		Username: "resetuser",
		Email:    &testEmail,
		Password: oldPassword,
	}
	_, err := localAuth.CreateUser(creds)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	t.Run("request password reset", func(t *testing.T) {
		form := url.Values{}
		form.Set("email", testEmail)

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
			t.Error("Expected success to be true")
		}
	})

	// Create a reset token manually for testing
	resetToken, err := tokenStore.CreateToken("", testEmail, oa.TokenTypePasswordReset, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create reset token: %v", err)
	}

	t.Run("reset password with valid token", func(t *testing.T) {
		form := url.Values{}
		form.Set("token", resetToken.Token)
		form.Set("password", newPassword)

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		// Verify old password no longer works
		localAuth.UsernameField = "email"
		user, err := localAuth.ValidateCredentials(testEmail, oldPassword, "")
		if err == nil || user != nil {
			t.Error("Old password should no longer work")
		}

		// Verify new password works
		user, err = localAuth.ValidateCredentials(testEmail, newPassword, "")
		if err != nil || user == nil {
			t.Errorf("New password should work, got error: %v", err)
		}
	})

	t.Run("reset password with invalid token", func(t *testing.T) {
		form := url.Values{}
		form.Set("token", "invalid-token")
		form.Set("password", "anotherpassword")

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})

	t.Run("reset password with weak password", func(t *testing.T) {
		// Create new token for this test
		newToken, err := tokenStore.CreateToken("", testEmail, oa.TokenTypePasswordReset, 1*time.Hour)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		form := url.Values{}
		form.Set("token", newToken.Token)
		form.Set("password", "weak")

		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		localAuth.HandleResetPassword(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})
}

// TestFileStorageIsolation verifies that different test instances don't interfere
func TestFileStorageIsolation(t *testing.T) {
	_, _, _, _, _, tmpDir1 := setupTestAuthComplete(t)
	defer cleanupTest(t, tmpDir1)

	_, _, _, _, _, tmpDir2 := setupTestAuthComplete(t)
	defer cleanupTest(t, tmpDir2)

	// Verify they use different directories
	if tmpDir1 == tmpDir2 {
		t.Error("Expected different temp directories for isolation")
	}

	// Verify directories exist and are isolated
	if _, err := os.Stat(tmpDir1); os.IsNotExist(err) {
		t.Errorf("Directory %s should exist", tmpDir1)
	}
	if _, err := os.Stat(tmpDir2); os.IsNotExist(err) {
		t.Errorf("Directory %s should exist", tmpDir2)
	}

	// Verify they're in different paths
	abs1, _ := filepath.Abs(tmpDir1)
	abs2, _ := filepath.Abs(tmpDir2)
	if abs1 == abs2 {
		t.Error("Absolute paths should be different")
	}
}
