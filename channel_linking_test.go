package oneauth_test

import (
	"os"
	"testing"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/stores/fs"
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

func TestUsernameStoreReserve(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	// Reserve a username
	err := store.ReserveUsername("JohnDoe", "user123")
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Lookup should work (case-insensitive)
	userID, err := store.GetUserByUsername("johndoe")
	if err != nil {
		t.Fatalf("Failed to lookup username: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got %q", userID)
	}

	// Lookup with original case should also work
	userID, err = store.GetUserByUsername("JohnDoe")
	if err != nil {
		t.Fatalf("Failed to lookup username with original case: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got %q", userID)
	}
}

func TestUsernameStoreDuplicateReservation(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	// Reserve a username
	err := store.ReserveUsername("testuser", "user123")
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Try to reserve same username for different user
	err = store.ReserveUsername("testuser", "user456")
	if err == nil {
		t.Error("Expected error for duplicate username reservation")
	}

	// Same user can re-reserve (update case)
	err = store.ReserveUsername("TestUser", "user123")
	if err != nil {
		t.Errorf("Same user should be able to update case: %v", err)
	}
}

func TestUsernameStoreCaseInsensitive(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	err := store.ReserveUsername("TestUser", "user123")
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Try different case variations
	err = store.ReserveUsername("TESTUSER", "user456")
	if err == nil {
		t.Error("Should not allow same username with different case for different user")
	}

	err = store.ReserveUsername("testuser", "user789")
	if err == nil {
		t.Error("Should not allow same username lowercase for different user")
	}
}

func TestUsernameStoreRelease(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	// Reserve and release
	store.ReserveUsername("releaseme", "user123")
	err := store.ReleaseUsername("releaseme")
	if err != nil {
		t.Fatalf("Failed to release username: %v", err)
	}

	// Should be available again
	err = store.ReserveUsername("releaseme", "user456")
	if err != nil {
		t.Errorf("Username should be available after release: %v", err)
	}
}

func TestUsernameStoreChange(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	// Reserve initial username
	err := store.ReserveUsername("oldname", "user123")
	if err != nil {
		t.Fatalf("Failed to reserve username: %v", err)
	}

	// Change to new username
	err = store.ChangeUsername("oldname", "newname", "user123")
	if err != nil {
		t.Fatalf("Failed to change username: %v", err)
	}

	// Old username should be available
	_, err = store.GetUserByUsername("oldname")
	if err == nil {
		t.Error("Old username should not exist after change")
	}

	// New username should work
	userID, err := store.GetUserByUsername("newname")
	if err != nil {
		t.Fatalf("New username lookup failed: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got %q", userID)
	}
}

func TestUsernameStoreChangeCaseOnly(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	store.ReserveUsername("myname", "user123")

	// Change case only
	err := store.ChangeUsername("myname", "MyName", "user123")
	if err != nil {
		t.Fatalf("Failed to change username case: %v", err)
	}

	// Should still work
	userID, err := store.GetUserByUsername("myname")
	if err != nil {
		t.Fatalf("Username lookup failed: %v", err)
	}
	if userID != "user123" {
		t.Errorf("Expected userID 'user123', got %q", userID)
	}
}

func TestUsernameStoreChangeToTaken(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	store.ReserveUsername("name1", "user1")
	store.ReserveUsername("name2", "user2")

	// Try to change to taken username
	err := store.ChangeUsername("name1", "name2", "user1")
	if err == nil {
		t.Error("Should not allow changing to a taken username")
	}
}

func TestUsernameStoreNotFound(t *testing.T) {
	store, tmpDir := setupUsernameStore(t)
	defer os.RemoveAll(tmpDir)

	_, err := store.GetUserByUsername("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent username")
	}
}

// =============================================================================
// NewEnsureAuthUserFunc Tests
// =============================================================================

func setupAuthStores(t *testing.T) (oa.EnsureAuthUserConfig, string) {
	tmpDir, err := os.MkdirTemp("", "oneauth-channel-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	return oa.EnsureAuthUserConfig{
		UserStore:     fs.NewFSUserStore(tmpDir),
		IdentityStore: fs.NewFSIdentityStore(tmpDir),
		ChannelStore:  fs.NewFSChannelStore(tmpDir),
		UsernameStore: fs.NewFSUsernameStore(tmpDir),
	}, tmpDir
}

func TestEnsureAuthUserNewUser(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := oa.NewEnsureAuthUserFunc(config)

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

func TestEnsureAuthUserExistingUserNewChannel(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := oa.NewEnsureAuthUserFunc(config)

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

func TestEnsureAuthUserMissingEmail(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := oa.NewEnsureAuthUserFunc(config)

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

func TestLinkLocalCredentials(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := oa.NewEnsureAuthUserFunc(config)

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
	err = oa.LinkLocalCredentials(config, user.Id(), "newusername", "password123", "oauth@example.com")
	if err != nil {
		t.Fatalf("Failed to link credentials: %v", err)
	}

	// Verify can login with password
	validator := oa.NewCredentialsValidator(config.IdentityStore, config.ChannelStore, config.UserStore)
	loggedInUser, err := validator("oauth@example.com", "password123", "email")
	if err != nil {
		t.Fatalf("Failed to login with linked credentials: %v", err)
	}
	if loggedInUser.Id() != user.Id() {
		t.Errorf("Expected same user ID, got %q and %q", user.Id(), loggedInUser.Id())
	}

	// Verify username was reserved
	userID, err := config.UsernameStore.GetUserByUsername("newusername")
	if err != nil {
		t.Fatalf("Failed to lookup username: %v", err)
	}
	if userID != user.Id() {
		t.Errorf("Username should map to user ID")
	}
}

func TestLinkLocalCredentialsAlreadyExists(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := oa.NewEnsureAuthUserFunc(config)

	// Create OAuth user
	userInfo := map[string]any{
		"email": "test@example.com",
	}
	user, _ := ensureUser("oauth", "google", nil, userInfo)

	// Link credentials first time
	err := oa.LinkLocalCredentials(config, user.Id(), "username1", "password123", "test@example.com")
	if err != nil {
		t.Fatalf("First link should succeed: %v", err)
	}

	// Try to link again - should fail
	err = oa.LinkLocalCredentials(config, user.Id(), "username2", "password456", "test@example.com")
	if err == nil {
		t.Error("Should not allow linking credentials twice")
	}
}

func TestLinkLocalCredentialsWrongEmail(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := oa.NewEnsureAuthUserFunc(config)

	// Create user
	userInfo := map[string]any{
		"email": "user@example.com",
	}
	user, _ := ensureUser("oauth", "google", nil, userInfo)

	// Try to link with different email
	err := oa.LinkLocalCredentials(config, user.Id(), "username", "password123", "wrong@example.com")
	if err == nil {
		t.Error("Should not allow linking with wrong email")
	}
}

// =============================================================================
// NewCredentialsValidatorWithUsername Tests
// =============================================================================

func TestCredentialsValidatorWithUsername(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := oa.NewEnsureAuthUserFunc(config)

	// Create OAuth user and link local credentials
	userInfo := map[string]any{
		"email": "test@example.com",
	}
	user, _ := ensureUser("oauth", "google", nil, userInfo)
	oa.LinkLocalCredentials(config, user.Id(), "testuser", "password123", "test@example.com")

	// Create validator with username support
	validator := oa.NewCredentialsValidatorWithUsername(
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

func TestCredentialsValidatorWithUsernameWrongPassword(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	ensureUser := oa.NewEnsureAuthUserFunc(config)

	userInfo := map[string]any{"email": "test@example.com"}
	user, _ := ensureUser("oauth", "google", nil, userInfo)
	oa.LinkLocalCredentials(config, user.Id(), "testuser", "password123", "test@example.com")

	validator := oa.NewCredentialsValidatorWithUsername(
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

func TestCredentialsValidatorNoUsernameStore(t *testing.T) {
	config, tmpDir := setupAuthStores(t)
	defer os.RemoveAll(tmpDir)

	// Create validator without username store
	validator := oa.NewCredentialsValidatorWithUsername(
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
