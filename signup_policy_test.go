package oneauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/stores/fs"
	"golang.org/x/oauth2"
)

// =============================================================================
// SignupPolicy Tests
// =============================================================================

func TestSignupPolicyDefaults(t *testing.T) {
	policy := oa.DefaultSignupPolicy()

	if policy.RequireUsername {
		t.Error("Expected RequireUsername to be false by default")
	}
	if !policy.RequireEmail {
		t.Error("Expected RequireEmail to be true by default")
	}
	if policy.RequirePhone {
		t.Error("Expected RequirePhone to be false by default")
	}
	if !policy.RequirePassword {
		t.Error("Expected RequirePassword to be true by default")
	}
	if policy.MinPasswordLength != 8 {
		t.Errorf("Expected MinPasswordLength to be 8, got %d", policy.MinPasswordLength)
	}
}

func TestSignupPolicyPresets(t *testing.T) {
	// Test PolicyUsernameRequired
	if !oa.PolicyUsernameRequired.RequireUsername {
		t.Error("PolicyUsernameRequired should require username")
	}
	if !oa.PolicyUsernameRequired.RequireEmail {
		t.Error("PolicyUsernameRequired should require email")
	}

	// Test PolicyEmailOnly
	if oa.PolicyEmailOnly.RequireUsername {
		t.Error("PolicyEmailOnly should not require username")
	}
	if !oa.PolicyEmailOnly.RequireEmail {
		t.Error("PolicyEmailOnly should require email")
	}

	// Test PolicyFlexible
	if oa.PolicyFlexible.RequireUsername {
		t.Error("PolicyFlexible should not require username")
	}
	if oa.PolicyFlexible.RequireEmail {
		t.Error("PolicyFlexible should not require email")
	}
	if oa.PolicyFlexible.RequirePassword {
		t.Error("PolicyFlexible should not require password")
	}
}

func TestSignupPolicyGetUsernamePattern(t *testing.T) {
	policy := oa.SignupPolicy{
		UsernamePattern: `^[a-z]+$`,
	}

	pattern := policy.GetUsernamePattern()
	if !pattern.MatchString("abc") {
		t.Error("Pattern should match 'abc'")
	}
	if pattern.MatchString("ABC") {
		t.Error("Pattern should not match 'ABC'")
	}
	if pattern.MatchString("abc123") {
		t.Error("Pattern should not match 'abc123'")
	}

	// Test default pattern
	defaultPolicy := oa.SignupPolicy{}
	defaultPattern := defaultPolicy.GetUsernamePattern()
	if !defaultPattern.MatchString("user_name-123") {
		t.Error("Default pattern should match 'user_name-123'")
	}
}

func TestSignupPolicyGetMinPasswordLength(t *testing.T) {
	policy := oa.SignupPolicy{MinPasswordLength: 12}
	if policy.GetMinPasswordLength() != 12 {
		t.Errorf("Expected MinPasswordLength 12, got %d", policy.GetMinPasswordLength())
	}

	// Test default
	zeroPolicy := oa.SignupPolicy{}
	if zeroPolicy.GetMinPasswordLength() != 8 {
		t.Errorf("Expected default MinPasswordLength 8, got %d", zeroPolicy.GetMinPasswordLength())
	}
}

// =============================================================================
// SignupPolicy Integration Tests
// =============================================================================

func TestSignupWithPolicyEmailOnly(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oneauth-policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)

	policy := oa.PolicyEmailOnly
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(userStore, identityStore, channelStore),
		SignupPolicy: &policy,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "user": userInfo})
		},
	}

	// Signup without username should succeed
	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	localAuth.HandleSignup(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestSignupWithPolicyUsernameRequired(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oneauth-policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)

	policy := oa.PolicyUsernameRequired
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(userStore, identityStore, channelStore),
		SignupPolicy: &policy,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		},
	}

	// Signup without username should fail
	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	localAuth.HandleSignup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var response map[string]any
	json.NewDecoder(rr.Body).Decode(&response)
	if response["code"] != oa.ErrCodeMissingField {
		t.Errorf("Expected error code %q, got %q", oa.ErrCodeMissingField, response["code"])
	}
	if response["field"] != "username" {
		t.Errorf("Expected field 'username', got %q", response["field"])
	}
}

func TestSignupPolicyPasswordLength(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oneauth-policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)

	policy := oa.SignupPolicy{
		RequireEmail:      true,
		RequirePassword:   true,
		MinPasswordLength: 12,
	}
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(userStore, identityStore, channelStore),
		SignupPolicy: &policy,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		},
	}

	// Password with 10 chars should fail (need 12)
	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "1234567890") // 10 chars

	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	localAuth.HandleSignup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var response map[string]any
	json.NewDecoder(rr.Body).Decode(&response)
	if response["code"] != oa.ErrCodeWeakPassword {
		t.Errorf("Expected error code %q, got %q", oa.ErrCodeWeakPassword, response["code"])
	}
}

// =============================================================================
// AuthError Tests
// =============================================================================

func TestAuthErrorInterface(t *testing.T) {
	err := oa.NewAuthError(oa.ErrCodeEmailExists, "Email already exists", "email")

	// Test error interface
	if err.Error() != "Email already exists" {
		t.Errorf("Error() should return message, got %q", err.Error())
	}

	// Test fields
	if err.Code != oa.ErrCodeEmailExists {
		t.Errorf("Expected code %q, got %q", oa.ErrCodeEmailExists, err.Code)
	}
	if err.Field != "email" {
		t.Errorf("Expected field 'email', got %q", err.Field)
	}
}

func TestAuthErrorHandler(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oneauth-error-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)

	// Track if custom handler was called
	handlerCalled := false
	capturedError := (*oa.AuthError)(nil)

	policy := oa.PolicyEmailOnly
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(userStore, identityStore, channelStore),
		SignupPolicy: &policy,
		OnSignupError: func(err *oa.AuthError, w http.ResponseWriter, r *http.Request) bool {
			handlerCalled = true
			capturedError = err
			// Custom response
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte("Custom error page"))
			return true
		},
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		},
	}

	// Trigger validation error (invalid email)
	form := url.Values{}
	form.Set("email", "invalid-email")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	localAuth.HandleSignup(rr, req)

	if !handlerCalled {
		t.Error("Custom error handler was not called")
	}
	if capturedError == nil {
		t.Error("Error was not passed to handler")
	} else if capturedError.Code != oa.ErrCodeInvalidEmail {
		t.Errorf("Expected error code %q, got %q", oa.ErrCodeInvalidEmail, capturedError.Code)
	}
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected status 422, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Custom error page") {
		t.Errorf("Expected custom response, got: %s", rr.Body.String())
	}
}

func TestDefaultErrorHandlerJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oneauth-error-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)

	policy := oa.PolicyEmailOnly
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(userStore, identityStore, channelStore),
		SignupPolicy: &policy,
		// No OnSignupError - should use default JSON response
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		},
	}

	// Trigger validation error
	form := url.Values{}
	form.Set("email", "invalid-email")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	localAuth.HandleSignup(rr, req)

	// Should return JSON with error details
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var response map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if response["code"] == nil {
		t.Error("Response should contain 'code' field")
	}
	if response["error"] == nil {
		t.Error("Response should contain 'error' field")
	}
	if response["field"] == nil {
		t.Error("Response should contain 'field' field")
	}
}

// =============================================================================
// Error Codes Tests
// =============================================================================

func TestErrorCodes(t *testing.T) {
	// Just verify the constants are defined
	codes := []string{
		oa.ErrCodeEmailExists,
		oa.ErrCodeUsernameTaken,
		oa.ErrCodeWeakPassword,
		oa.ErrCodeInvalidUsername,
		oa.ErrCodeInvalidEmail,
		oa.ErrCodeInvalidPhone,
		oa.ErrCodeMissingField,
		oa.ErrCodeInvalidCreds,
	}

	for _, code := range codes {
		if code == "" {
			t.Error("Error code should not be empty")
		}
	}
}
