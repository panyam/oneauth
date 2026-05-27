// Package federatedauth owns provider-mediated authentication orchestration —
// OAuth and SAML callback handlers plus account-linking helpers — that build
// on the account model in accounts/ and the session/middleware machinery in
// httpauth/.
package federatedauth

import (
	"context"
	"fmt"
	"log"

	"github.com/panyam/oneauth/accounts"
)

// EnsureAuthUserConfig holds configuration for NewEnsureAuthUserFunc.
type EnsureAuthUserConfig struct {
	UserStore     accounts.UserStore
	IdentityStore accounts.IdentityStore
	ChannelStore  accounts.ChannelStore
	UsernameStore accounts.UsernameStore
}

// EnsureAuthUserFunc handles user creation/lookup for both OAuth and local
// authentication with channel linking support.
type EnsureAuthUserFunc func(authtype string, provider string, token any, userInfo map[string]any) (accounts.User, error)

// NewEnsureAuthUserFunc creates a function that handles user creation/lookup
// for both OAuth and local authentication with channel linking support.
func NewEnsureAuthUserFunc(config EnsureAuthUserConfig) EnsureAuthUserFunc {
	return func(authtype string, provider string, token any, userInfo map[string]any) (accounts.User, error) {
		ctx := context.Background()
		email, _ := userInfo["email"].(string)
		if email == "" {
			return nil, fmt.Errorf("email is required for authentication")
		}

		identityType := "email"
		identityKey := accounts.IdentityKey(identityType, email)

		idResp, err := config.IdentityStore.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: identityType, IdentityValue: email})

		if err == nil && idResp != nil && idResp.Identity != nil && idResp.Identity.UserID != "" {
			return handleExistingUser(ctx, config, idResp.Identity, authtype, provider, identityKey, userInfo)
		}

		return handleNewUser(ctx, config, authtype, provider, identityType, email, identityKey, userInfo)
	}
}

func handleExistingUser(ctx context.Context, config EnsureAuthUserConfig, identity *accounts.Identity, authtype, provider, identityKey string, userInfo map[string]any) (accounts.User, error) {
	userResp, err := config.UserStore.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: identity.UserID})
	if err != nil {
		return nil, fmt.Errorf("failed to get user for identity (%v): %w", identity, err)
	}
	user := userResp.User

	chResp, err := config.ChannelStore.GetChannel(ctx, &accounts.GetChannelRequest{Provider: provider, IdentityKey: identityKey, CreateIfMissing: true})
	if err != nil {
		return nil, fmt.Errorf("failed to get/create channel: %w", err)
	}
	channel := chResp.Channel
	isNew := chResp.NewCreated

	if channel.Profile == nil {
		channel.Profile = make(map[string]any)
	}
	for k, v := range userInfo {
		channel.Profile[k] = v
	}
	if _, err := config.ChannelStore.SaveChannel(ctx, &accounts.SaveChannelRequest{Channel: channel}); err != nil {
		return nil, fmt.Errorf("failed to save channel: %w", err)
	}

	profile := user.Profile()
	if profile == nil {
		profile = make(map[string]any)
	}
	channels := accounts.LinkedChannels(profile)
	if !containsString(channels, provider) {
		channels = append(channels, provider)
		profile["channels"] = channels

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
		if _, err := config.UserStore.SaveUser(ctx, &accounts.SaveUserRequest{User: updatedUser}); err != nil {
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

func handleNewUser(ctx context.Context, config EnsureAuthUserConfig, authtype, provider, identityType, email, identityKey string, userInfo map[string]any) (accounts.User, error) {
	userId, err := newSecureUserId()
	if err != nil {
		return nil, err
	}

	profile := map[string]any{
		"email":    email,
		"channels": []string{provider},
	}

	if name, ok := userInfo["name"].(string); ok && name != "" {
		profile["name"] = name
	}
	if picture, ok := userInfo["picture"].(string); ok && picture != "" {
		profile["picture"] = picture
	}
	if username, ok := userInfo["username"].(string); ok && username != "" {
		profile["username"] = username
	}

	userResp, err := config.UserStore.CreateUser(ctx, &accounts.CreateUserRequest{UserID: userId, IsActive: true, Profile: profile})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	user := userResp.User

	identity := &accounts.Identity{
		Type:     identityType,
		Value:    email,
		UserID:   userId,
		Verified: authtype == "oauth",
	}
	if _, err := config.IdentityStore.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: identity}); err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	channel := &accounts.Channel{
		Provider:    provider,
		IdentityKey: identityKey,
		Credentials: make(map[string]any),
		Profile:     userInfo,
	}
	if _, err := config.ChannelStore.SaveChannel(ctx, &accounts.SaveChannelRequest{Channel: channel}); err != nil {
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
