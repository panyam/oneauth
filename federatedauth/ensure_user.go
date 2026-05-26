// Package federatedauth owns provider-mediated authentication orchestration —
// OAuth and SAML callback handlers plus account-linking helpers — that build
// on the account model in accounts/ and the session/middleware machinery in
// httpauth/.
//
// What this package owns:
//   - SaveUserAndRedirect          — entry point OAuth/SAML callbacks call after token exchange
//   - HandleLinkOAuthCallback      — links a new provider channel to an existing user
//   - LinkOAuthConfig              — config for the linking flow
//   - StartLinkOAuth / GetLinkingUserID — session bookkeeping for the linking flow
//   - AuthUserStore                — composite store interface for callbacks
//   - EnsureAuthUserConfig / NewEnsureAuthUserFunc — provider-driven user creation
//
// What this package deliberately does NOT own:
//   - Username/password flows — see localauth/
//   - The account data model (User/Identity/Channel) — see accounts/
//   - Session/cookie/CSRF machinery — see httpauth/
package federatedauth

import (
	"fmt"
	"log"

	"github.com/panyam/oneauth/accounts"
)

// =============================================================================
// Channel-aware user creation
// =============================================================================

// EnsureAuthUserConfig holds configuration for NewEnsureAuthUserFunc.
//
// Example setup in your app:
//
//	config := federatedauth.EnsureAuthUserConfig{
//	    UserStore:     gaeStores.UserStore,
//	    IdentityStore: gaeStores.IdentityStore,
//	    ChannelStore:  gaeStores.ChannelStore,
//	    UsernameStore: gaeStores.UsernameStore, // optional
//	}
//	ensureUser := federatedauth.NewEnsureAuthUserFunc(config)
type EnsureAuthUserConfig struct {
	UserStore     accounts.UserStore
	IdentityStore accounts.IdentityStore
	ChannelStore  accounts.ChannelStore
	UsernameStore accounts.UsernameStore // Optional — for username uniqueness
}

// EnsureAuthUserFunc handles user creation/lookup for both OAuth and local
// authentication with channel linking support. Returned by
// NewEnsureAuthUserFunc; passed to the AuthUserStore implementations callbacks
// supply to SaveUserAndRedirect.
type EnsureAuthUserFunc func(authtype string, provider string, token any, userInfo map[string]any) (accounts.User, error)

// NewEnsureAuthUserFunc creates a function that handles user creation/lookup for both
// OAuth and local authentication with channel linking support.
//
// # Who Calls This
//
// This function is called by SaveUserAndRedirect after a successful OAuth callback
// or local login. The returned function implements the core logic for AuthUserStore.EnsureAuthUser.
//
// # Flow for OAuth (e.g., Google Login)
//
//  1. User clicks "Login with Google" → redirects to Google
//  2. Google redirects back to /auth/google/callback with auth code
//  3. OAuth handler exchanges code for token, fetches userInfo (email, name, picture)
//  4. OAuth handler calls SaveUserAndRedirect(authtype="oauth", provider="google", token, userInfo)
//  5. SaveUserAndRedirect calls UserStore.EnsureAuthUser → this function
//  6. This function checks if email identity exists:
//     - EXISTS: Link Google channel to existing user, update profile["channels"]
//     - NEW: Create User, Identity (verified=true), Google Channel
//  7. SaveUserAndRedirect creates JWT, sets cookies, redirects to app
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
func NewEnsureAuthUserFunc(config EnsureAuthUserConfig) EnsureAuthUserFunc {
	return func(authtype string, provider string, token any, userInfo map[string]any) (accounts.User, error) {
		// Extract email from userInfo (primary identifier for linking)
		email, _ := userInfo["email"].(string)
		if email == "" {
			return nil, fmt.Errorf("email is required for authentication")
		}

		identityType := "email"
		identityKey := accounts.IdentityKey(identityType, email)

		// Check if identity already exists
		identity, _, err := config.IdentityStore.GetIdentity(identityType, email, false)

		if err == nil && identity != nil && identity.UserID != "" {
			// Existing user — link new channel if needed
			return handleExistingUser(config, identity, authtype, provider, identityKey, userInfo)
		}

		// New user — create user, identity, and channel
		return handleNewUser(config, authtype, provider, identityType, email, identityKey, userInfo)
	}
}

// handleExistingUser links a new auth channel to an existing user.
func handleExistingUser(config EnsureAuthUserConfig, identity *accounts.Identity, authtype, provider, identityKey string, userInfo map[string]any) (accounts.User, error) {
	user, err := config.UserStore.GetUserById(identity.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user for identity (%v): %w", identity, err)
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
	channels := accounts.LinkedChannels(profile)
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

		updatedUser := &accounts.BasicUser{ID: user.Id(), ProfileData: profile}
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

// handleNewUser creates a new user with identity and channel.
func handleNewUser(config EnsureAuthUserConfig, authtype, provider, identityType, email, identityKey string, userInfo map[string]any) (accounts.User, error) {
	userId, err := newSecureUserId()
	if err != nil {
		return nil, err
	}

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

	user, err := config.UserStore.CreateUser(userId, true, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	identity := &accounts.Identity{
		Type:     identityType,
		Value:    email,
		UserID:   userId,
		Verified: authtype == "oauth", // OAuth-verified emails are trusted
	}
	if err := config.IdentityStore.SaveIdentity(identity); err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	channel := &accounts.Channel{
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

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
