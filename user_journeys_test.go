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
// User Journey Tests
// These tests verify complete user flows as documented in AUTH_FLOWS.md
// =============================================================================

// TestJourney represents a test environment for user journey tests
type TestJourney struct {
	TmpDir        string
	UserStore     *fs.FSUserStore
	IdentityStore *fs.FSIdentityStore
	ChannelStore  *fs.FSChannelStore
	TokenStore    *fs.FSTokenStore
	UsernameStore *fs.FSUsernameStore

	// EnsureUser handles OAuth user creation/lookup
	EnsureUser func(authtype string, provider string, token any, userInfo map[string]any) (oa.User, error)
	Config     oa.EnsureAuthUserConfig
}

func setupJourney(t *testing.T) *TestJourney {
	tmpDir, err := os.MkdirTemp("", "oneauth-journey-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)
	tokenStore := fs.NewFSTokenStore(tmpDir)
	usernameStore := fs.NewFSUsernameStore(tmpDir)

	config := oa.EnsureAuthUserConfig{
		UserStore:     userStore,
		IdentityStore: identityStore,
		ChannelStore:  channelStore,
		UsernameStore: usernameStore,
	}

	return &TestJourney{
		TmpDir:        tmpDir,
		UserStore:     userStore,
		IdentityStore: identityStore,
		ChannelStore:  channelStore,
		TokenStore:    tokenStore,
		UsernameStore: usernameStore,
		EnsureUser:    oa.NewEnsureAuthUserFunc(config),
		Config:        config,
	}
}

func (j *TestJourney) Cleanup() {
	os.RemoveAll(j.TmpDir)
}

// Helper to get a pointer to a SignupPolicy
func policyPtr(p oa.SignupPolicy) *oa.SignupPolicy {
	return &p
}

// =============================================================================
// Journey 1: Multiple OAuth Providers (Same Email = Same Account)
// =============================================================================

func TestJourney1_MultipleOAuthSameEmail(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "alice@gmail.com"

	// Day 1: User logs in with Google
	googleUserInfo := map[string]any{
		"email": email,
		"name":  "Alice via Google",
	}
	user1, err := j.EnsureUser("oauth", "google", nil, googleUserInfo)
	if err != nil {
		t.Fatalf("Google login failed: %v", err)
	}
	user1ID := user1.Id()
	t.Logf("Created user via Google: %s", user1ID)

	// Verify Google channel exists
	identityKey := oa.IdentityKey("email", email)
	googleChannel, _, err := j.ChannelStore.GetChannel("google", identityKey, false)
	if err != nil || googleChannel == nil {
		t.Error("Google channel should exist")
	}

	// Day 7: Same user logs in with GitHub (same email!)
	githubUserInfo := map[string]any{
		"email": email,
		"name":  "Alice via GitHub",
	}
	user2, err := j.EnsureUser("oauth", "github", nil, githubUserInfo)
	if err != nil {
		t.Fatalf("GitHub login failed: %v", err)
	}
	user2ID := user2.Id()

	// CRITICAL: Should be the SAME user!
	if user1ID != user2ID {
		t.Errorf("Expected SAME user ID for same email, got %s and %s", user1ID, user2ID)
	}

	// Verify both channels exist for the same identity
	githubChannel, _, err := j.ChannelStore.GetChannel("github", identityKey, false)
	if err != nil || githubChannel == nil {
		t.Error("GitHub channel should exist")
	}

	// Verify channels list in profile
	profile := user2.Profile()
	channels := getChannelsFromProfile(profile)
	if len(channels) != 2 {
		t.Errorf("Expected 2 channels, got %d: %v", len(channels), channels)
	}
	if !containsString(channels, "google") {
		t.Error("Should have 'google' channel")
	}
	if !containsString(channels, "github") {
		t.Error("Should have 'github' channel")
	}

	t.Log("Journey 1 PASSED: Multiple OAuth providers with same email = same account")
}

// =============================================================================
// Journey 2: OAuth User Adds Username + Password
// =============================================================================

func TestJourney2_OAuthUserAddsCredentials(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "bob@gmail.com"

	// Day 1: User logs in with Google (OAuth only)
	oauthUserInfo := map[string]any{
		"email": email,
		"name":  "Bob",
	}
	user, err := j.EnsureUser("oauth", "google", nil, oauthUserInfo)
	if err != nil {
		t.Fatalf("OAuth login failed: %v", err)
	}
	userID := user.Id()
	t.Logf("Created OAuth user: %s", userID)

	// Verify NO local channel exists yet
	identityKey := oa.IdentityKey("email", email)
	localChannel, _, _ := j.ChannelStore.GetChannel("local", identityKey, false)
	if localChannel != nil {
		t.Error("Local channel should NOT exist yet for OAuth-only user")
	}

	// Day 3, Step 1: User sets username
	newUsername := "bobsmith"
	err = j.UsernameStore.ReserveUsername(newUsername, userID)
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Update profile with username
	profile := user.Profile()
	profile["username"] = newUsername
	if err := j.UserStore.SaveUser(user); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	// Verify username lookup works
	lookupUserID, err := j.UsernameStore.GetUserByUsername(newUsername)
	if err != nil {
		t.Fatalf("Username lookup failed: %v", err)
	}
	if lookupUserID != userID {
		t.Errorf("Username should map to user ID, got %s", lookupUserID)
	}

	// Day 3, Step 2: User sets password
	err = oa.LinkLocalCredentials(j.Config, userID, newUsername, "password123", email)
	if err != nil {
		t.Fatalf("Failed to link local credentials: %v", err)
	}

	// Verify local channel NOW exists
	localChannel, _, _ = j.ChannelStore.GetChannel("local", identityKey, false)
	if localChannel == nil {
		t.Error("Local channel should exist after linking credentials")
	}

	// Test: Can login with email + password
	validator := oa.NewCredentialsValidator(j.IdentityStore, j.ChannelStore, j.UserStore)
	loggedInUser, err := validator(email, "password123", "email")
	if err != nil {
		t.Fatalf("Email+password login failed: %v", err)
	}
	if loggedInUser.Id() != userID {
		t.Error("Should login to correct user with email")
	}

	// Test: Can login with username + password
	usernameValidator := oa.NewCredentialsValidatorWithUsername(
		j.IdentityStore, j.ChannelStore, j.UserStore, j.UsernameStore,
	)
	loggedInUser, err = usernameValidator(newUsername, "password123", "")
	if err != nil {
		t.Fatalf("Username+password login failed: %v", err)
	}
	if loggedInUser.Id() != userID {
		t.Error("Should login to correct user with username")
	}

	// Test: Can still login with OAuth (Google channel still works)
	user3, err := j.EnsureUser("oauth", "google", nil, oauthUserInfo)
	if err != nil {
		t.Fatalf("OAuth re-login failed: %v", err)
	}
	if user3.Id() != userID {
		t.Error("OAuth should login to same user")
	}

	t.Log("Journey 2 PASSED: OAuth user can add username + password and login 3 ways")
}

// =============================================================================
// Journey 3: Email Signup, Then Link OAuth
// =============================================================================

func TestJourney3_EmailSignupThenLinkOAuth(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "carol@example.com"
	password := "mypass123"

	// Create LocalAuth for signup
	policy := oa.DefaultSignupPolicy()
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(j.UserStore, j.IdentityStore, j.ChannelStore),
		SignupPolicy: &policy,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "user": userInfo})
		},
	}

	// Day 1: User signs up with email/password
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)

	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	localAuth.HandleSignup(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Signup failed: %s", rr.Body.String())
	}

	// Get the user ID from the identity
	identity, _, _ := j.IdentityStore.GetIdentity("email", email, false)
	user1ID := identity.UserID
	t.Logf("Created local user: %s", user1ID)

	// Verify local channel exists
	identityKey := oa.IdentityKey("email", email)
	localChannel, _, _ := j.ChannelStore.GetChannel("local", identityKey, false)
	if localChannel == nil {
		t.Error("Local channel should exist")
	}

	// Day 5: User logs in with Google (same email)
	googleUserInfo := map[string]any{
		"email": email,
		"name":  "Carol via Google",
	}
	user2, err := j.EnsureUser("oauth", "google", nil, googleUserInfo)
	if err != nil {
		t.Fatalf("Google login failed: %v", err)
	}

	// CRITICAL: Should be the SAME user!
	if user2.Id() != user1ID {
		t.Errorf("Expected same user ID, got %s and %s", user1ID, user2.Id())
	}

	// Verify both channels exist
	googleChannel, _, _ := j.ChannelStore.GetChannel("google", identityKey, false)
	if googleChannel == nil {
		t.Error("Google channel should exist after linking")
	}

	// User can now login with email+password OR Google
	validator := oa.NewCredentialsValidator(j.IdentityStore, j.ChannelStore, j.UserStore)
	loggedInUser, err := validator(email, password, "email")
	if err != nil {
		t.Fatalf("Email login should still work: %v", err)
	}
	if loggedInUser.Id() != user1ID {
		t.Error("Should login to correct user")
	}

	t.Log("Journey 3 PASSED: Email signup user can link OAuth with same email")
}

// =============================================================================
// Journey 4: Username as Primary Login
// =============================================================================

func TestJourney4_UsernameAsPrimaryLogin(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "dave@company.com"
	username := "davec"
	password := "securepass123"

	// Create user with email identity
	policy := oa.DefaultSignupPolicy()
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(j.UserStore, j.IdentityStore, j.ChannelStore),
		SignupPolicy: &policy,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "user": userInfo})
		},
	}

	// Signup
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	localAuth.HandleSignup(rr, req)

	identity, _, _ := j.IdentityStore.GetIdentity("email", email, false)
	userID := identity.UserID

	// Reserve username
	j.UsernameStore.ReserveUsername(username, userID)

	// Create validator with username support
	validator := oa.NewCredentialsValidatorWithUsername(
		j.IdentityStore, j.ChannelStore, j.UserStore, j.UsernameStore,
	)

	// Test: Login with email (has @)
	user, err := validator(email, password, "")
	if err != nil {
		t.Fatalf("Email login failed: %v", err)
	}
	if user.Id() != userID {
		t.Error("Email login should return correct user")
	}

	// Test: Login with username (no @)
	user, err = validator(username, password, "")
	if err != nil {
		t.Fatalf("Username login failed: %v", err)
	}
	if user.Id() != userID {
		t.Error("Username login should return correct user")
	}

	// Test: Login with wrong password fails
	_, err = validator(username, "wrongpassword", "")
	if err == nil {
		t.Error("Should fail with wrong password")
	}

	// Test: Login with non-existent username fails
	_, err = validator("nonexistent", password, "")
	if err == nil {
		t.Error("Should fail with non-existent username")
	}

	t.Log("Journey 4 PASSED: Can login with username or email")
}

// =============================================================================
// Journey 5: Different Emails = Different Accounts
// =============================================================================

func TestJourney5_DifferentEmailsDifferentAccounts(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	// Day 1: Login with Google (personal email)
	googleUserInfo := map[string]any{
		"email": "alice@gmail.com",
		"name":  "Alice Personal",
	}
	user1, err := j.EnsureUser("oauth", "google", nil, googleUserInfo)
	if err != nil {
		t.Fatalf("Google login failed: %v", err)
	}
	user1ID := user1.Id()

	// Day 3: Login with GitHub (work email - DIFFERENT!)
	githubUserInfo := map[string]any{
		"email": "alice@company.com",
		"name":  "Alice Work",
	}
	user2, err := j.EnsureUser("oauth", "github", nil, githubUserInfo)
	if err != nil {
		t.Fatalf("GitHub login failed: %v", err)
	}
	user2ID := user2.Id()

	// CRITICAL: Should be DIFFERENT users!
	if user1ID == user2ID {
		t.Errorf("Different emails should create different users, both got %s", user1ID)
	}

	t.Log("Journey 5 PASSED: Different emails = different accounts (by design)")
}

// =============================================================================
// Journey 6: Password Change
// =============================================================================

func TestJourney6_PasswordChange(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "user@example.com"
	oldPassword := "oldpassword123"
	newPassword := "newpassword456"

	// Create user with password
	policy := oa.DefaultSignupPolicy()
	localAuth := &oa.LocalAuth{
		CreateUser:     oa.NewCreateUserFunc(j.UserStore, j.IdentityStore, j.ChannelStore),
		SignupPolicy:   &policy,
		UpdatePassword: oa.NewUpdatePasswordFunc(j.IdentityStore, j.ChannelStore),
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		},
	}

	// Signup
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", oldPassword)
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	localAuth.HandleSignup(rr, req)

	// Verify old password works
	validator := oa.NewCredentialsValidator(j.IdentityStore, j.ChannelStore, j.UserStore)
	_, err := validator(email, oldPassword, "email")
	if err != nil {
		t.Fatalf("Old password should work: %v", err)
	}

	// Change password
	err = localAuth.UpdatePassword(email, newPassword)
	if err != nil {
		t.Fatalf("Password change failed: %v", err)
	}

	// Verify old password NO LONGER works
	_, err = validator(email, oldPassword, "email")
	if err == nil {
		t.Error("Old password should NOT work after change")
	}

	// Verify new password works
	_, err = validator(email, newPassword, "email")
	if err != nil {
		t.Fatalf("New password should work: %v", err)
	}

	t.Log("Journey 6 PASSED: Password change works correctly")
}

// =============================================================================
// Journey 7: Username Change
// =============================================================================

func TestJourney7_UsernameChange(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	userID := "user123"
	oldUsername := "oldname"
	newUsername := "newname"

	// Reserve initial username
	err := j.UsernameStore.ReserveUsername(oldUsername, userID)
	if err != nil {
		t.Fatalf("Failed to reserve initial username: %v", err)
	}

	// Verify it works
	foundUserID, _ := j.UsernameStore.GetUserByUsername(oldUsername)
	if foundUserID != userID {
		t.Error("Initial username should map to user")
	}

	// Change username
	err = j.UsernameStore.ChangeUsername(oldUsername, newUsername, userID)
	if err != nil {
		t.Fatalf("Username change failed: %v", err)
	}

	// Verify old username NO LONGER works
	_, err = j.UsernameStore.GetUserByUsername(oldUsername)
	if err == nil {
		t.Error("Old username should NOT exist after change")
	}

	// Verify new username works
	foundUserID, err = j.UsernameStore.GetUserByUsername(newUsername)
	if err != nil {
		t.Fatalf("New username lookup failed: %v", err)
	}
	if foundUserID != userID {
		t.Error("New username should map to same user")
	}

	t.Log("Journey 7 PASSED: Username change works correctly")
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestEdgeCase_DuplicateEmailSignup(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "existing@example.com"

	policy := oa.DefaultSignupPolicy()
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(j.UserStore, j.IdentityStore, j.ChannelStore),
		SignupPolicy: &policy,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		},
	}

	// First signup succeeds
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	localAuth.HandleSignup(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("First signup should succeed: %s", rr.Body.String())
	}

	// Second signup with same email should fail
	req = httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	localAuth.HandleSignup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Second signup should fail, got status %d: %s", rr.Code, rr.Body.String())
	}

	var response map[string]any
	json.NewDecoder(rr.Body).Decode(&response)
	if response["code"] != oa.ErrCodeEmailExists {
		t.Errorf("Expected error code %q, got %q", oa.ErrCodeEmailExists, response["code"])
	}
}

func TestEdgeCase_OAuthReturnsExistingEmail(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "shared@example.com"

	// Create local user first
	policy := oa.DefaultSignupPolicy()
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(j.UserStore, j.IdentityStore, j.ChannelStore),
		SignupPolicy: &policy,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		},
	}

	form := url.Values{}
	form.Set("email", email)
	form.Set("password", "password123")
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	localAuth.HandleSignup(rr, req)

	identity, _, _ := j.IdentityStore.GetIdentity("email", email, false)
	localUserID := identity.UserID

	// OAuth login with same email should link to existing user
	oauthUserInfo := map[string]any{
		"email": email,
		"name":  "OAuth User",
	}
	oauthUser, err := j.EnsureUser("oauth", "google", nil, oauthUserInfo)
	if err != nil {
		t.Fatalf("OAuth login should succeed: %v", err)
	}

	// Should be SAME user
	if oauthUser.Id() != localUserID {
		t.Errorf("OAuth should link to existing user, got %s instead of %s", oauthUser.Id(), localUserID)
	}

	// User now has both channels
	identityKey := oa.IdentityKey("email", email)
	localChannel, _, _ := j.ChannelStore.GetChannel("local", identityKey, false)
	googleChannel, _, _ := j.ChannelStore.GetChannel("google", identityKey, false)

	if localChannel == nil {
		t.Error("Local channel should still exist")
	}
	if googleChannel == nil {
		t.Error("Google channel should be added")
	}
}

func TestEdgeCase_LinkCredentialsTwiceFails(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "oauth@example.com"

	// Create OAuth user
	oauthUserInfo := map[string]any{"email": email}
	user, _ := j.EnsureUser("oauth", "google", nil, oauthUserInfo)
	userID := user.Id()

	// First link succeeds
	err := oa.LinkLocalCredentials(j.Config, userID, "username1", "password123", email)
	if err != nil {
		t.Fatalf("First link should succeed: %v", err)
	}

	// Second link should fail
	err = oa.LinkLocalCredentials(j.Config, userID, "username2", "password456", email)
	if err == nil {
		t.Error("Second link should fail - local channel already exists")
	}
}

func TestEdgeCase_UsernameAlreadyTaken(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	// User 1 reserves "coolname"
	err := j.UsernameStore.ReserveUsername("coolname", "user1")
	if err != nil {
		t.Fatalf("First reservation should succeed: %v", err)
	}

	// User 2 tries to reserve same name
	err = j.UsernameStore.ReserveUsername("coolname", "user2")
	if err == nil {
		t.Error("Should not allow duplicate username")
	}

	// Case-insensitive: "COOLNAME" should also fail
	err = j.UsernameStore.ReserveUsername("COOLNAME", "user3")
	if err == nil {
		t.Error("Should not allow same username with different case")
	}
}

func TestEdgeCase_AutoDetectEmailVsUsername(t *testing.T) {
	j := setupJourney(t)
	defer j.Cleanup()

	email := "user@example.com"
	username := "myusername"
	password := "password123"

	// Create user with local auth
	policy := oa.DefaultSignupPolicy()
	localAuth := &oa.LocalAuth{
		CreateUser:   oa.NewCreateUserFunc(j.UserStore, j.IdentityStore, j.ChannelStore),
		SignupPolicy: &policy,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		},
	}

	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	localAuth.HandleSignup(rr, req)

	identity, _, _ := j.IdentityStore.GetIdentity("email", email, false)
	userID := identity.UserID

	// Reserve username
	j.UsernameStore.ReserveUsername(username, userID)

	// Create validator
	validator := oa.NewCredentialsValidatorWithUsername(
		j.IdentityStore, j.ChannelStore, j.UserStore, j.UsernameStore,
	)

	// Test: Input with "@" treated as email
	user, err := validator(email, password, "")
	if err != nil {
		t.Fatalf("Email (with @) login failed: %v", err)
	}
	if user.Id() != userID {
		t.Error("Should find user by email")
	}

	// Test: Input without "@" treated as username
	user, err = validator(username, password, "")
	if err != nil {
		t.Fatalf("Username (no @) login failed: %v", err)
	}
	if user.Id() != userID {
		t.Error("Should find user by username")
	}

	// Test: Explicit field override still works
	user, err = validator(email, password, "email")
	if err != nil {
		t.Fatalf("Explicit email field login failed: %v", err)
	}
	if user.Id() != userID {
		t.Error("Should find user with explicit email field")
	}
}
