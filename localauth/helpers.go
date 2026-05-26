package localauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/panyam/oneauth/accounts"
	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is used for timing oracle prevention (CWE-208).
// When a user is not found, we still run bcrypt against this dummy hash
// so the response time matches that of a real user lookup.
// This is a valid bcrypt hash of "dummy" — the actual value doesn't matter,
// only that bcrypt.CompareHashAndPassword runs in constant time.
var dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("oneauth-timing-dummy"), bcrypt.DefaultCost)

// NewCreateUserFunc creates a CreateUserFunc from stores.
func NewCreateUserFunc(userStore accounts.UserStore, identityStore accounts.IdentityStore, channelStore accounts.ChannelStore) CreateUserFunc {
	return func(creds *Credentials) (accounts.User, error) {
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
		identity = &accounts.Identity{
			Type:     identityType,
			Value:    identityValue,
			UserID:   userId,
			Verified: false,
		}
		if err := identityStore.SaveIdentity(identity); err != nil {
			return nil, fmt.Errorf("failed to create identity: %w", err)
		}

		// Create local channel with password
		identityKey := accounts.IdentityKey(identityType, identityValue)
		channel := &accounts.Channel{
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

// NewCredentialsValidator creates a CredentialsValidator from stores.
func NewCredentialsValidator(identityStore accounts.IdentityStore, channelStore accounts.ChannelStore, userStore accounts.UserStore) CredentialsValidator {
	return func(username, password, usernameType string) (accounts.User, error) {
		// Auto-detect username type if not specified
		if usernameType == "" {
			usernameType = DetectUsernameType(username)
		}

		// For username type, search is not implemented yet
		if usernameType == "username" {
			return nil, fmt.Errorf("username login not yet implemented - please use email or phone")
		}

		// For email/phone, lookup identity directly
		identityKey := accounts.IdentityKey(usernameType, username)

		// Get local channel for this identity
		channel, _, err := channelStore.GetChannel("local", identityKey, false)
		if err != nil {
			// Timing oracle fix (CWE-208): run bcrypt against a dummy hash
			// so response time is constant regardless of whether the user exists.
			// Without this, non-existent users return instantly (~1ms) while
			// existing users take ~50ms (bcrypt), allowing username enumeration.
			bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
			return nil, fmt.Errorf("invalid credentials")
		}

		// Verify password
		passwordHash, ok := channel.Credentials["password_hash"].(string)
		if !ok {
			bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
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

// NewVerifyEmailFunc creates a VerifyEmailFunc from stores.
func NewVerifyEmailFunc(identityStore accounts.IdentityStore, tokenStore VerificationTokenStore) VerifyEmailFunc {
	return func(token string) error {
		verToken, err := tokenStore.GetToken(token)
		if err != nil {
			return fmt.Errorf("invalid or expired token")
		}

		if verToken.Type != VerificationTypeEmail {
			return fmt.Errorf("invalid token type")
		}

		// Mark the email identity as verified
		if err := identityStore.MarkIdentityVerified("email", verToken.Email); err != nil {
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
func NewUpdatePasswordFunc(identityStore accounts.IdentityStore, channelStore accounts.ChannelStore) UpdatePasswordFunc {
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
		identityKey := accounts.IdentityKey("email", email)
		channel, _, err := channelStore.GetChannel("local", identityKey, false)
		if err != nil || channel == nil {
			channel = &accounts.Channel{
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

// generateSecureUserId generates a cryptographically secure user ID.
func generateSecureUserId() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// =============================================================================
// Credential Linking Helpers
// =============================================================================

// LinkLocalCredentialsConfig groups the stores LinkLocalCredentials needs.
// Self-contained so localauth doesn't have to import federatedauth just for
// the cross-cutting "add local password to an OAuth user" flow.
type LinkLocalCredentialsConfig struct {
	UserStore     accounts.UserStore
	IdentityStore accounts.IdentityStore
	ChannelStore  accounts.ChannelStore
	UsernameStore accounts.UsernameStore // Optional — reserves the username if set
}

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
// # What It Does
//
//  1. Verifies the email belongs to the given userID
//  2. Checks that local channel doesn't already exist
//  3. Creates local channel with hashed password
//  4. Reserves username in UsernameStore (if configured and username provided)
//  5. Updates user profile["channels"] to include "local"
func LinkLocalCredentials(config LinkLocalCredentialsConfig, userID string, username, password, email string) error {
	// Get existing identity
	identity, _, err := config.IdentityStore.GetIdentity("email", email, false)
	if err != nil {
		return fmt.Errorf("identity not found: %w", err)
	}
	if identity.UserID != userID {
		return fmt.Errorf("email does not belong to this user")
	}

	identityKey := accounts.IdentityKey("email", email)

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
	channel := &accounts.Channel{
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
	channels := accounts.LinkedChannels(profile)
	if !containsString(channels, "local") {
		channels = append(channels, "local")
		profile["channels"] = channels
	}
	if username != "" {
		profile["username"] = username
	}

	updatedUser := &accounts.BasicUser{ID: userID, ProfileData: profile}
	if err := config.UserStore.SaveUser(updatedUser); err != nil {
		log.Printf("Warning: failed to update user profile: %v", err)
	}

	log.Printf("Linked local credentials to user %s", userID)
	return nil
}

// NewCredentialsValidatorWithUsername creates a CredentialsValidator that supports
// logging in with username (in addition to email/phone).
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
func NewCredentialsValidatorWithUsername(identityStore accounts.IdentityStore, channelStore accounts.ChannelStore, userStore accounts.UserStore, usernameStore accounts.UsernameStore) CredentialsValidator {
	return func(username, password, usernameType string) (accounts.User, error) {
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
			var emailIdentity *accounts.Identity
			for _, id := range identities {
				if id.Type == "email" {
					emailIdentity = id
					break
				}
			}
			if emailIdentity == nil {
				return nil, fmt.Errorf("invalid credentials")
			}
			identityKey = accounts.IdentityKey("email", emailIdentity.Value)
		} else {
			// For email/phone, lookup identity directly
			identityKey = accounts.IdentityKey(usernameType, username)
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

		// Get identity and user via parsed identity key
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

// parseIdentityKey splits "type:value" into [type, value].
func parseIdentityKey(key string) []string {
	for i, c := range key {
		if c == ':' {
			return []string{key[:i], key[i+1:]}
		}
	}
	return nil
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
