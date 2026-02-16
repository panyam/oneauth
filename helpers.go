package oneauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// NewCreateUserFunc creates a CreateUserFunc from stores
func NewCreateUserFunc(userStore UserStore, identityStore IdentityStore, channelStore ChannelStore) CreateUserFunc {
	return func(creds *Credentials) (User, error) {
		// Determine primary identity
		var identityType, identityValue string
		if creds.Email != nil && *creds.Email != "" {
			identityType = "email"
			identityValue = *creds.Email
		} else if creds.Phone != nil && *creds.Phone != "" {
			identityType = "phone"
			identityValue = *creds.Phone
		} else {
			return nil, fmt.Errorf("email or phone required")
		}

		// Check if identity already exists
		identity, _, err := identityStore.GetIdentity(identityType, identityValue, false)
		if err == nil && identity != nil {
			return nil, fmt.Errorf("%s already registered", identityType)
		}

		// Hash password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}

		// Create user
		userId := generateSecureUserId()
		profile := map[string]any{
			"username": creds.Username,
		}
		if creds.Email != nil {
			profile["email"] = *creds.Email
		}
		if creds.Phone != nil {
			profile["phone"] = *creds.Phone
		}

		user, err := userStore.CreateUser(userId, true, profile)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		// Create identity
		identity = &Identity{
			Type:     identityType,
			Value:    identityValue,
			UserID:   userId,
			Verified: false,
		}
		if err := identityStore.SaveIdentity(identity); err != nil {
			return nil, fmt.Errorf("failed to create identity: %w", err)
		}

		// Create local channel with password
		identityKey := IdentityKey(identityType, identityValue)
		channel := &Channel{
			Provider:    "local",
			IdentityKey: identityKey,
			Credentials: map[string]any{
				"password_hash": string(passwordHash),
				"username":      creds.Username,
			},
			Profile: profile,
		}
		if err := channelStore.SaveChannel(channel); err != nil {
			return nil, fmt.Errorf("failed to create channel: %w", err)
		}

		log.Printf("Created local user %s with identity %s", userId, identityKey)
		return user, nil
	}
}

// NewCredentialsValidator creates a CredentialsValidator from stores
func NewCredentialsValidator(identityStore IdentityStore, channelStore ChannelStore, userStore UserStore) CredentialsValidator {
	return func(username, password, usernameType string) (User, error) {
		// Auto-detect username type if not specified
		if usernameType == "" {
			usernameType = DetectUsernameType(username)
		}

		// For username type, search is not implemented yet
		if usernameType == "username" {
			return nil, fmt.Errorf("username login not yet implemented - please use email or phone")
		}

		// For email/phone, lookup identity directly
		identityKey := IdentityKey(usernameType, username)

		// Get local channel for this identity
		channel, _, err := channelStore.GetChannel("local", identityKey, false)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}

		// Verify password
		passwordHash, ok := channel.Credentials["password_hash"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid credentials")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		// Get identity and user
		identity, _, err := identityStore.GetIdentity(usernameType, username, false)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}

		return userStore.GetUserById(identity.UserID)
	}
}

// NewVerifyEmailFunc creates a VerifyEmailFunc from stores
func NewVerifyEmailFunc(identityStore IdentityStore, tokenStore TokenStore) VerifyEmailFunc {
	return func(token string) error {
		authToken, err := tokenStore.GetToken(token)
		if err != nil {
			return fmt.Errorf("invalid or expired token")
		}

		if authToken.Type != TokenTypeEmailVerification {
			return fmt.Errorf("invalid token type")
		}

		// Mark the email identity as verified
		if err := identityStore.MarkIdentityVerified("email", authToken.Email); err != nil {
			return fmt.Errorf("failed to verify email: %w", err)
		}

		// Delete the token (one-time use)
		if err := tokenStore.DeleteToken(token); err != nil {
			log.Printf("Warning: failed to delete token: %v", err)
		}

		return nil
	}
}

// NewUpdatePasswordFunc creates an UpdatePasswordFunc from stores.
// If the user has no local channel (e.g. OAuth-only user), one is created automatically.
func NewUpdatePasswordFunc(identityStore IdentityStore, channelStore ChannelStore) UpdatePasswordFunc {
	return func(email, newPassword string) error {
		// Get the identity
		identity, _, err := identityStore.GetIdentity("email", email, false)
		if err != nil {
			return fmt.Errorf("user not found")
		}

		// Hash new password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		// Get or create local channel (supports OAuth-only users setting a password via reset)
		identityKey := IdentityKey("email", email)
		channel, _, err := channelStore.GetChannel("local", identityKey, false)
		if err != nil || channel == nil {
			channel = &Channel{
				Provider:    "local",
				IdentityKey: identityKey,
				Credentials: map[string]any{},
				Profile: map[string]any{
					"email": email,
				},
			}
			log.Printf("Creating local channel for user %s (password set via reset)", identity.UserID)
		}

		// Update password
		channel.Credentials["password_hash"] = string(passwordHash)
		if err := channelStore.SaveChannel(channel); err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}

		log.Printf("Password updated for user %s", identity.UserID)
		return nil
	}
}

// generateSecureUserId generates a cryptographically secure user ID
func generateSecureUserId() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// =============================================================================
// Channel-Aware User Creation (Phase 4)
// =============================================================================

// EnsureAuthUserConfig holds configuration for NewEnsureAuthUserFunc.
//
// Example setup in your app:
//
//	config := oneauth.EnsureAuthUserConfig{
//	    UserStore:     gaeStores.UserStore,
//	    IdentityStore: gaeStores.IdentityStore,
//	    ChannelStore:  gaeStores.ChannelStore,
//	    UsernameStore: gaeStores.UsernameStore, // optional
//	}
//	ensureUser := oneauth.NewEnsureAuthUserFunc(config)
//
//	// Then use with OneAuth:
//	authUserStore := &MyAuthUserStore{config: config, ensureUser: ensureUser}
//	oneAuth.UserStore = authUserStore
type EnsureAuthUserConfig struct {
	UserStore     UserStore
	IdentityStore IdentityStore
	ChannelStore  ChannelStore
	UsernameStore UsernameStore // Optional - for username uniqueness
}

// NewEnsureAuthUserFunc creates a function that handles user creation/lookup for both
// OAuth and local authentication with channel linking support.
//
// # Who Calls This
//
// This function is called by OneAuth.SaveUserAndRedirect after a successful OAuth callback
// or local login. The returned function implements the core logic for AuthUserStore.EnsureAuthUser.
//
// # Flow for OAuth (e.g., Google Login)
//
//  1. User clicks "Login with Google" → redirects to Google
//  2. Google redirects back to /auth/google/callback with auth code
//  3. OAuth handler exchanges code for token, fetches userInfo (email, name, picture)
//  4. OAuth handler calls OneAuth.SaveUserAndRedirect(authtype="oauth", provider="google", token, userInfo)
//  5. SaveUserAndRedirect calls UserStore.EnsureAuthUser → this function
//  6. This function checks if email identity exists:
//     - EXISTS: Link Google channel to existing user, update profile["channels"]
//     - NEW: Create User, Identity (verified=true), Google Channel
//  7. SaveUserAndRedirect creates JWT, sets cookies, redirects to app
//
// # Flow for Local Signup
//
//  1. User submits signup form with email/password
//  2. LocalAuth.HandleSignup validates and calls CreateUser (from NewCreateUserFunc)
//  3. CreateUser creates User, Identity (verified=false), Local Channel
//  4. HandleSignup calls HandleUser → SaveUserAndRedirect → this function
//  5. User is logged in (or email verification required)
//
// # Channel Linking Logic
//
// Multiple channels (local, google, github) can point to the same user via shared email:
//
//	User (id: abc123)
//	├── Identity: email → user@example.com
//	├── Channel: local → email:user@example.com (password_hash)
//	├── Channel: google → email:user@example.com (oauth profile)
//	└── Channel: github → email:user@example.com (oauth profile)
//
// User profile tracks linked providers: profile["channels"] = ["local", "google", "github"]
func NewEnsureAuthUserFunc(config EnsureAuthUserConfig) func(authtype string, provider string, token any, userInfo map[string]any) (User, error) {
	return func(authtype string, provider string, token any, userInfo map[string]any) (User, error) {
		// Extract email from userInfo (primary identifier for linking)
		email, _ := userInfo["email"].(string)
		if email == "" {
			return nil, fmt.Errorf("email is required for authentication")
		}

		identityType := "email"
		identityKey := IdentityKey(identityType, email)

		// Check if identity already exists
		identity, _, err := config.IdentityStore.GetIdentity(identityType, email, false)

		if err == nil && identity != nil && identity.UserID != "" {
			// Existing user - link new channel if needed
			return handleExistingUser(config, identity, authtype, provider, identityKey, userInfo)
		}

		// New user - create user, identity, and channel
		return handleNewUser(config, authtype, provider, identityType, email, identityKey, userInfo)
	}
}

// handleExistingUser links a new auth channel to an existing user
func handleExistingUser(config EnsureAuthUserConfig, identity *Identity, authtype, provider, identityKey string, userInfo map[string]any) (User, error) {
	// Get existing user
	user, err := config.UserStore.GetUserById(identity.UserID)
	log.Println("User Store: ", config.UserStore)
	if err != nil {
		return nil, fmt.Errorf("failed to get user for identity (%v): : %w", identity, err)
	}

	// Check if channel already exists for this provider
	channel, isNew, err := config.ChannelStore.GetChannel(provider, identityKey, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create channel: %w", err)
	}

	// Update channel with latest OAuth info
	if channel.Profile == nil {
		channel.Profile = make(map[string]any)
	}
	for k, v := range userInfo {
		channel.Profile[k] = v
	}
	if err := config.ChannelStore.SaveChannel(channel); err != nil {
		return nil, fmt.Errorf("failed to save channel: %w", err)
	}

	// Update user profile with linked channels
	profile := user.Profile()
	if profile == nil {
		profile = make(map[string]any)
	}
	channels := getLinkedChannels(profile)
	if !containsString(channels, provider) {
		channels = append(channels, provider)
		profile["channels"] = channels

		// Update other profile fields from OAuth if not set
		if profile["name"] == nil || profile["name"] == "" {
			if name, ok := userInfo["name"].(string); ok && name != "" {
				profile["name"] = name
			}
		}
		if profile["picture"] == nil || profile["picture"] == "" {
			if picture, ok := userInfo["picture"].(string); ok && picture != "" {
				profile["picture"] = picture
			}
		}

		// Save updated user
		updatedUser := &BasicUser{id: user.Id(), profile: profile}
		if err := config.UserStore.SaveUser(updatedUser); err != nil {
			log.Printf("Warning: failed to update user profile: %v", err)
		}
	}

	if isNew {
		log.Printf("Linked %s channel to existing user %s", provider, identity.UserID)
	} else {
		log.Printf("User %s logged in via %s channel", identity.UserID, provider)
	}

	return user, nil
}

// handleNewUser creates a new user with identity and channel
func handleNewUser(config EnsureAuthUserConfig, authtype, provider, identityType, email, identityKey string, userInfo map[string]any) (User, error) {
	userId := generateSecureUserId()

	// Build initial profile
	profile := map[string]any{
		"email":    email,
		"channels": []string{provider},
	}

	// Copy relevant fields from OAuth userInfo
	if name, ok := userInfo["name"].(string); ok && name != "" {
		profile["name"] = name
	}
	if picture, ok := userInfo["picture"].(string); ok && picture != "" {
		profile["picture"] = picture
	}
	if username, ok := userInfo["username"].(string); ok && username != "" {
		profile["username"] = username
	}

	// Create user
	user, err := config.UserStore.CreateUser(userId, true, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create identity (verified for OAuth)
	identity := &Identity{
		Type:     identityType,
		Value:    email,
		UserID:   userId,
		Verified: authtype == "oauth", // OAuth-verified emails are trusted
	}
	if err := config.IdentityStore.SaveIdentity(identity); err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	// Create channel
	channel := &Channel{
		Provider:    provider,
		IdentityKey: identityKey,
		Credentials: make(map[string]any),
		Profile:     userInfo,
	}
	if err := config.ChannelStore.SaveChannel(channel); err != nil {
		return nil, fmt.Errorf("failed to create channel: %w", err)
	}

	log.Printf("Created new user %s via %s with identity %s", userId, provider, identityKey)
	return user, nil
}

// getLinkedChannels extracts the channels list from user profile
func getLinkedChannels(profile map[string]any) []string {
	if profile == nil {
		return []string{}
	}

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

// containsString checks if a slice contains a string
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// =============================================================================
// Credential Linking Helpers
// =============================================================================

// LinkLocalCredentials adds local (password) authentication to an existing OAuth-only user.
// This enables "incremental auth" where users sign up via OAuth and later add a password.
//
// # Who Calls This
//
// Your app calls this from a "Set Password" or "Complete Profile" page. Typically:
//
//  1. User signed up via Google OAuth (has google channel, no local channel)
//  2. User visits profile page, sees "Add password for email login"
//  3. User submits password (and optionally username) form
//  4. Your handler calls LinkLocalCredentials with the logged-in user's ID
//  5. User can now login with email/password OR Google
//
// # Example Handler in Your App
//
//	func handleSetPassword(w http.ResponseWriter, r *http.Request) {
//	    userID := getLoggedInUserID(r) // from session/JWT
//	    user, _ := userStore.GetUserById(userID)
//	    email := user.Profile()["email"].(string)
//
//	    username := r.FormValue("username") // optional
//	    password := r.FormValue("password")
//
//	    err := oneauth.LinkLocalCredentials(config, userID, username, password, email)
//	    if err != nil {
//	        // handle error (e.g., username taken, password too weak)
//	    }
//	    // redirect to profile with success message
//	}
//
// # What It Does
//
//  1. Verifies the email belongs to the given userID
//  2. Checks that local channel doesn't already exist
//  3. Creates local channel with hashed password
//  4. Reserves username in UsernameStore (if configured and username provided)
//  5. Updates user profile["channels"] to include "local"
func LinkLocalCredentials(config EnsureAuthUserConfig, userID string, username, password, email string) error {
	// Get existing identity
	identity, _, err := config.IdentityStore.GetIdentity("email", email, false)
	if err != nil {
		return fmt.Errorf("identity not found: %w", err)
	}
	if identity.UserID != userID {
		return fmt.Errorf("email does not belong to this user")
	}

	identityKey := IdentityKey("email", email)

	// Check if local channel already exists
	existingChannel, _, err := config.ChannelStore.GetChannel("local", identityKey, false)
	if err == nil && existingChannel != nil {
		return fmt.Errorf("local credentials already exist for this user")
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create local channel
	channel := &Channel{
		Provider:    "local",
		IdentityKey: identityKey,
		Credentials: map[string]any{
			"password_hash": string(passwordHash),
		},
		Profile: map[string]any{
			"email": email,
		},
	}
	if username != "" {
		channel.Credentials["username"] = username
		channel.Profile["username"] = username
	}

	if err := config.ChannelStore.SaveChannel(channel); err != nil {
		return fmt.Errorf("failed to create local channel: %w", err)
	}

	// Reserve username if store configured and username provided
	if username != "" && config.UsernameStore != nil {
		if err := config.UsernameStore.ReserveUsername(username, userID); err != nil {
			log.Printf("Warning: failed to reserve username: %v", err)
			// Don't fail - channel was created successfully
		}
	}

	// Update user profile to include local channel
	user, err := config.UserStore.GetUserById(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	profile := user.Profile()
	if profile == nil {
		profile = make(map[string]any)
	}
	channels := getLinkedChannels(profile)
	if !containsString(channels, "local") {
		channels = append(channels, "local")
		profile["channels"] = channels
	}
	if username != "" {
		profile["username"] = username
	}

	updatedUser := &BasicUser{id: userID, profile: profile}
	if err := config.UserStore.SaveUser(updatedUser); err != nil {
		log.Printf("Warning: failed to update user profile: %v", err)
	}

	log.Printf("Linked local credentials to user %s", userID)
	return nil
}

// NewCredentialsValidatorWithUsername creates a CredentialsValidator that supports
// logging in with username (in addition to email/phone).
//
// # Who Calls This
//
// Use this instead of NewCredentialsValidator when setting up LocalAuth if you want
// users to be able to login with their username:
//
//	localAuth := &oneauth.LocalAuth{
//	    ValidateCredentials: oneauth.NewCredentialsValidatorWithUsername(
//	        identityStore, channelStore, userStore, usernameStore,
//	    ),
//	    // ... other config
//	}
//
// # How Username Login Works
//
//  1. User enters "johndoe" and password on login form
//  2. DetectUsernameType returns "username" (not email, not phone)
//  3. This validator looks up "johndoe" in UsernameStore → gets userID
//  4. Gets user's email identity from IdentityStore
//  5. Gets local channel for that email identity
//  6. Verifies password against channel's password_hash
//  7. Returns the user
//
// # Fallback Behavior
//
// If user enters an email or phone number instead of username, it falls back to
// the standard email/phone lookup (same as NewCredentialsValidator).
func NewCredentialsValidatorWithUsername(identityStore IdentityStore, channelStore ChannelStore, userStore UserStore, usernameStore UsernameStore) CredentialsValidator {
	return func(username, password, usernameType string) (User, error) {
		// Auto-detect username type if not specified
		if usernameType == "" {
			usernameType = DetectUsernameType(username)
		}

		var identityKey string

		// For username type, lookup via UsernameStore
		if usernameType == "username" {
			if usernameStore == nil {
				return nil, fmt.Errorf("username login not configured")
			}
			userID, err := usernameStore.GetUserByUsername(username)
			if err != nil {
				return nil, fmt.Errorf("invalid credentials")
			}

			// Get user's identities to find the primary email
			identities, err := identityStore.GetUserIdentities(userID)
			if err != nil || len(identities) == 0 {
				return nil, fmt.Errorf("invalid credentials")
			}

			// Find email identity
			var emailIdentity *Identity
			for _, id := range identities {
				if id.Type == "email" {
					emailIdentity = id
					break
				}
			}
			if emailIdentity == nil {
				return nil, fmt.Errorf("invalid credentials")
			}
			identityKey = IdentityKey("email", emailIdentity.Value)
		} else {
			// For email/phone, lookup identity directly
			identityKey = IdentityKey(usernameType, username)
		}

		// Get local channel for this identity
		channel, _, err := channelStore.GetChannel("local", identityKey, false)
		if err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		// Verify password
		passwordHash, ok := channel.Credentials["password_hash"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid credentials")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		// Get identity and user
		// Parse identity key to get type and value
		parts := parseIdentityKey(identityKey)
		if parts == nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		identity, _, err := identityStore.GetIdentity(parts[0], parts[1], false)
		if err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		return userStore.GetUserById(identity.UserID)
	}
}

// parseIdentityKey splits "type:value" into [type, value]
func parseIdentityKey(key string) []string {
	for i, c := range key {
		if c == ':' {
			return []string{key[:i], key[i+1:]}
		}
	}
	return nil
}
