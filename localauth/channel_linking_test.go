// Tests for username reservation, OAuth channel linking, local credential
// linking, and the credentials validator with username support.
package localauth_test

import (
	"github.com/panyam/oneauth/accounts"
	"context"
	"github.com/panyam/oneauth/localauth"
	"os"
	"testing"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/panyam/oneauth/federatedauth"
)

// =============================================================================
// UsernameStore Tests (using FS implementation)
// =============================================================================

func setupUsernameStore(t *testing.T) (*fs.FSUsernameStore, string) {
	tmpDir, err := os.MkdirTemp("", "oneauth-username-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return fs.NewFSUsernameStore(tmpDir), tmpDir
}

// TestUsernameStoreReserve verifies that a username can be reserved and looked up case-insensitively.
func TestUsernameStoreReserve(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	// Reserve a username
	_, err := store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "JohnDoe", UserID: "user123"})
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Lookup should work (case-insensitive)
	userIDResp_, err := store.GetUserByUsername(context.Background(), &accounts.GetUserByUsernameRequest{Username: "johndoe"})
	var userID string
	if userIDResp_ != nil { userID = userIDResp_.UserID }
	if err != nil {
		t.Fatalf("Failed to lookup username: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got %q", userID)
	}

	// Lookup with original case should also work
	userIDResp2, err := store.GetUserByUsername(context.Background(), &accounts.GetUserByUsernameRequest{Username: "JohnDoe"})
	userID = ""
	if userIDResp2 != nil { userID = userIDResp2.UserID }
	if err != nil {
		t.Fatalf("Failed to lookup username with original case: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got %q", userID)
	}
}

// TestUsernameStoreDuplicateReservation verifies that a different user cannot reserve an already-taken
// username, but the same user can update the casing of their own username.
func TestUsernameStoreDuplicateReservation(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	// Reserve a username
	_, err := store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "testuser", UserID: "user123"})
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Try to reserve same username for different user
	_, err = store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "testuser", UserID: "user456"})
	if err == nil {
		t.Error("Expected error for duplicate username reservation")
	}

	// Same user can re-reserve (update case)
	_, err = store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "TestUser", UserID: "user123"})
	if err != nil {
		t.Errorf("Same user should be able to update case: %v", err)
	}
}

// TestUsernameStoreCaseInsensitive verifies that username uniqueness is enforced case-insensitively.
func TestUsernameStoreCaseInsensitive(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	_, err := store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "TestUser", UserID: "user123"})
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Try different case variations
	_, err = store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "TESTUSER", UserID: "user456"})
	if err == nil {
		t.Error("Should not allow same username with different case for different user")
	}

	_, err = store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "testuser", UserID: "user789"})
	if err == nil {
		t.Error("Should not allow same username lowercase for different user")
	}
}

// TestUsernameStoreRelease verifies that releasing a username makes it available for another user.
func TestUsernameStoreRelease(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	// Reserve and release
	store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "releaseme", UserID: "user123"})
	_, err := store.ReleaseUsername(context.Background(), &accounts.ReleaseUsernameRequest{Username: "releaseme"})
	if err != nil {
		t.Fatalf("Failed to release username: %v", err)
	}

	// Should be available again
	_, err = store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "releaseme", UserID: "user456"})
	if err != nil {
		t.Errorf("Username should be available after release: %v", err)
	}
}

// TestUsernameStoreChange verifies that changing a username releases the old one and reserves the new one.
func TestUsernameStoreChange(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	// Reserve initial username
	_, err := store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "oldname", UserID: "user123"})
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Change to new username
	_, err = store.ChangeUsername(context.Background(), &accounts.ChangeUsernameRequest{OldUsername: "oldname", NewUsername: "newname", UserID: "user123"})
	if err != nil {
		t.Fatalf("Failed to change username: %v", err)
	}

	// Old username should be available
	_Resp_, err := store.GetUserByUsername(context.Background(), &accounts.GetUserByUsernameRequest{Username: "oldname"})
	_ = ""
	if _Resp_ != nil { _ = _Resp_.UserID }
	if err == nil {
		t.Error("Old username should not exist after change")
	}

	// New username should work
	userIDResp_, err := store.GetUserByUsername(context.Background(), &accounts.GetUserByUsernameRequest{Username: "newname"})
	var userID string
	if userIDResp_ != nil { userID = userIDResp_.UserID }
	if err != nil {
		t.Fatalf("New username lookup failed: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got %q", userID)
	}
}

// TestUsernameStoreChangeCaseOnly verifies that a user can change only the casing of their username.
func TestUsernameStoreChangeCaseOnly(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "myname", UserID: "user123"})

	// Change case only
	_, err := store.ChangeUsername(context.Background(), &accounts.ChangeUsernameRequest{OldUsername: "myname", NewUsername: "MyName", UserID: "user123"})
	if err != nil {
		t.Fatalf("Failed to change username case: %v", err)
	}

	// Should still work
	userIDResp_, err := store.GetUserByUsername(context.Background(), &accounts.GetUserByUsernameRequest{Username: "myname"})
	var userID string
	if userIDResp_ != nil { userID = userIDResp_.UserID }
	if err != nil {
		t.Fatalf("Username lookup failed: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got %q", userID)
	}
}

// TestUsernameStoreChangeToTaken verifies that changing to a username already reserved by another user fails.
func TestUsernameStoreChangeToTaken(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "name1", UserID: "user1"})
	store.ReserveUsername(context.Background(), &accounts.ReserveUsernameRequest{Username: "name2", UserID: "user2"})

	// Try to change to taken username
	_, err := store.ChangeUsername(context.Background(), &accounts.ChangeUsernameRequest{OldUsername: "name1", NewUsername: "name2", UserID: "user1"})
	if err == nil {
		t.Error("Should not allow changing to a taken username")
	}
}

// TestUsernameStoreNotFound verifies that looking up a non-existent username returns an error.
func TestUsernameStoreNotFound(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	_Resp_, err := store.GetUserByUsername(context.Background(), &accounts.GetUserByUsernameRequest{Username: "nonexistent"})
	var _ string
	if _Resp_ != nil { _ = _Resp_.UserID }
	if err == nil {
		t.Error("Expected error for non-existent username")
	}
}

// =============================================================================
// NewEnsureAuthUserFunc Tests
// =============================================================================

func setupAuthStores(t *testing.T) (federatedauth.EnsureAuthUserConfig, string) {
	tmpDir, err := os.MkdirTemp("", "oneauth-channel-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	return federatedauth.EnsureAuthUserConfig{
		UserStore:     fs.NewFSUserStore(tmpDir),
		IdentityStore: fs.NewFSIdentityStore(tmpDir),
		ChannelStore:  fs.NewFSChannelStore(tmpDir),
		UsernameStore: fs.NewFSUsernameStore(tmpDir),
	}, tmpDir
}

// TestEnsureAuthUserNewUser verifies that EnsureAuthUser creates a new user with profile and channel
// when no matching identity exists.
func TestEnsureAuthUserNewUser(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)

	userInfo := map[string]any{
		"email":   "new@example.com",
		"name":    "New User",
		"picture": "https://example.com/pic.jpg",
	}

	user, err := ensureUser("oauth", "google", nil, userInfo)
	if err != nil {
		t.Fatalf("Failed to create new user: %v", err)
	}

	if user == nil {
		t.Fatal("User should not be nil")
	}

	// Check profile
	profile := user.Profile()
	if profile["email"] != "new@example.com" {
		t.Errorf("Expected email in profile, got %v", profile["email"])
	}
	if profile["name"] != "New User" {
		t.Errorf("Expected name in profile, got %v", profile["name"])
	}

	// Check channels list
	channels, ok := profile["channels"].([]string)
	if !ok {
		t.Fatal("Channels should be []string")
	}
	if len(channels) != 1 || channels[0] != "google" {
		t.Errorf("Expected channels ['google'], got %v", channels)
	}
}

// TestEnsureAuthUserExistingUserNewChannel verifies that logging in via a second OAuth provider
// with the same email links to the existing user and adds the new channel.
func TestEnsureAuthUserExistingUserNewChannel(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)

	// Create user via Google
	userInfo := map[string]any{
		"email": "existing@example.com",
		"name":  "Existing User",
	}
	user1, err := ensureUser("oauth", "google", nil, userInfo)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Login via GitHub with same email - should link to same user
	userInfo2 := map[string]any{
		"email": "existing@example.com",
		"name":  "GitHub Name",
	}
	user2, err := ensureUser("oauth", "github", nil, userInfo2)
	if err != nil {
		t.Fatalf("Failed to link GitHub: %v", err)
	}

	// Should be same user
	if user1.Id() != user2.Id() {
		t.Errorf("Expected same user ID, got %q and %q", user1.Id(), user2.Id())
	}

	// Check channels list updated
	profile := user2.Profile()
	channels := getChannelsFromProfile(profile)
	if len(channels) != 2 {
		t.Errorf("Expected 2 channels, got %d: %v", len(channels), channels)
	}
	if !containsString(channels, "google") || !containsString(channels, "github") {
		t.Errorf("Expected google and github in channels, got %v", channels)
	}
}

// TestEnsureAuthUserMissingEmail verifies that EnsureAuthUser fails when userInfo has no email.
func TestEnsureAuthUserMissingEmail(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)

	userInfo := map[string]any{
		"name": "No Email User",
	}

	_, err := ensureUser("oauth", "google", nil, userInfo)
	if err == nil {
		t.Error("Should fail when email is missing")
	}
}

// =============================================================================
// LinkLocalCredentials Tests
// =============================================================================

// TestLinkLocalCredentials verifies that an OAuth-only user can add local credentials (username + password)
// and subsequently log in with them.
func TestLinkLocalCredentials(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)

	// Create OAuth-only user
	userInfo := map[string]any{
		"email": "oauth@example.com",
		"name":  "OAuth User",
	}
	user, err := ensureUser("oauth", "google", nil, userInfo)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Link local credentials
	err = localauth.LinkLocalCredentials(localauth.LinkLocalCredentialsConfig(config), user.Id(), "newusername", "password123", "oauth@example.com")
	if err != nil {
		t.Fatalf("Failed to link credentials: %v", err)
	}

	// Verify can login with password
	validator := localauth.NewCredentialsValidator(config.IdentityStore, config.ChannelStore, config.UserStore)
	loggedInUser, err := validator("oauth@example.com", "password123", "email")
	if err != nil {
		t.Fatalf("Failed to login with linked credentials: %v", err)
	}
	if loggedInUser.Id() != user.Id() {
		t.Errorf("Expected same user ID, got %q and %q", user.Id(), loggedInUser.Id())
	}

	// Verify username was reserved
	userIDResp_, err := config.UsernameStore.GetUserByUsername(context.Background(), &accounts.GetUserByUsernameRequest{Username: "newusername"})
	var userID string
	if userIDResp_ != nil { userID = userIDResp_.UserID }
	if err != nil {
		t.Fatalf("Failed to lookup username: %v", err)
	}
	if userID != user.Id() {
		t.Errorf("Username should map to user ID")
	}
}

// TestLinkLocalCredentialsAlreadyExists verifies that linking local credentials a second time is rejected.
func TestLinkLocalCredentialsAlreadyExists(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)

	// Create OAuth user
	userInfo := map[string]any{
		"email": "test@example.com",
	}
	user, _ := ensureUser("oauth", "google", nil, userInfo)

	// Link credentials first time
	err := localauth.LinkLocalCredentials(localauth.LinkLocalCredentialsConfig(config), user.Id(), "username1", "password123", "test@example.com")
	if err != nil {
		t.Fatalf("First link should succeed: %v", err)
	}

	// Try to link again - should fail
	err = localauth.LinkLocalCredentials(localauth.LinkLocalCredentialsConfig(config), user.Id(), "username2", "password456", "test@example.com")
	if err == nil {
		t.Error("Should not allow linking credentials twice")
	}
}

// TestLinkLocalCredentialsWrongEmail verifies that linking credentials fails when the provided email
// does not match the user's registered email identity.
func TestLinkLocalCredentialsWrongEmail(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)

	// Create user
	userInfo := map[string]any{
		"email": "user@example.com",
	}
	user, _ := ensureUser("oauth", "google", nil, userInfo)

	// Try to link with different email
	err := localauth.LinkLocalCredentials(localauth.LinkLocalCredentialsConfig(config), user.Id(), "username", "password123", "wrong@example.com")
	if err == nil {
		t.Error("Should not allow linking with wrong email")
	}
}

// =============================================================================
// NewCredentialsValidatorWithUsername Tests
// =============================================================================

// TestCredentialsValidatorWithUsername verifies that the username-aware credentials validator
// supports login via both username and email.
func TestCredentialsValidatorWithUsername(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)

	// Create OAuth user and link local credentials
	userInfo := map[string]any{
		"email": "test@example.com",
	}
	user, _ := ensureUser("oauth", "google", nil, userInfo)
	localauth.LinkLocalCredentials(localauth.LinkLocalCredentialsConfig(config), user.Id(), "testuser", "password123", "test@example.com")

	// Create validator with username support
	validator := localauth.NewCredentialsValidatorWithUsername(
		config.IdentityStore,
		config.ChannelStore,
		config.UserStore,
		config.UsernameStore,
	)

	// Login with username
	loggedInUser, err := validator("testuser", "password123", "username")
	if err != nil {
		t.Fatalf("Failed to login with username: %v", err)
	}
	if loggedInUser.Id() != user.Id() {
		t.Error("Should login to correct user")
	}

	// Login with email should also work
	loggedInUser, err = validator("test@example.com", "password123", "email")
	if err != nil {
		t.Fatalf("Failed to login with email: %v", err)
	}
	if loggedInUser.Id() != user.Id() {
		t.Error("Should login to correct user")
	}
}

// TestCredentialsValidatorWithUsernameWrongPassword verifies that username login fails with an incorrect password.
func TestCredentialsValidatorWithUsernameWrongPassword(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)

	userInfo := map[string]any{"email": "test@example.com"}
	user, _ := ensureUser("oauth", "google", nil, userInfo)
	localauth.LinkLocalCredentials(localauth.LinkLocalCredentialsConfig(config), user.Id(), "testuser", "password123", "test@example.com")

	validator := localauth.NewCredentialsValidatorWithUsername(
		config.IdentityStore,
		config.ChannelStore,
		config.UserStore,
		config.UsernameStore,
	)

	_, err := validator("testuser", "wrongpassword", "username")
	if err == nil {
		t.Error("Should fail with wrong password")
	}
}

// TestCredentialsValidatorNoUsernameStore verifies that username-based login fails gracefully
// when no UsernameStore is configured.
func TestCredentialsValidatorNoUsernameStore(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	// Create validator without username store
	validator := localauth.NewCredentialsValidatorWithUsername(
		config.IdentityStore,
		config.ChannelStore,
		config.UserStore,
		nil, // No UsernameStore
	)

	_, err := validator("someuser", "password", "username")
	if err == nil {
		t.Error("Should fail when UsernameStore is nil")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func getChannelsFromProfile(profile map[string]any) []string {
	switch v := profile["channels"].(type) {
	case []string:
		return v
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return []string{}
	}
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
