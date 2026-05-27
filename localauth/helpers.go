package localauth

import (
	"context"
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
var dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("oneauth-timing-dummy"), bcrypt.DefaultCost)

// NewCreateUserFunc creates a CreateUserFunc from stores.
func NewCreateUserFunc(userStore accounts.UserStore, identityStore accounts.IdentityStore, channelStore accounts.ChannelStore) CreateUserFunc {
	return func(creds *Credentials) (accounts.User, error) {
		ctx := context.Background()

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

		idResp, err := identityStore.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: identityType, IdentityValue: identityValue})
		if err == nil && idResp != nil && idResp.Identity != nil {
			return nil, fmt.Errorf("%s already registered", identityType)
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}

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

		userResp, err := userStore.CreateUser(ctx, &accounts.CreateUserRequest{UserID: userId, IsActive: true, Profile: profile})
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
		user := userResp.User

		identity := &accounts.Identity{
			Type:     identityType,
			Value:    identityValue,
			UserID:   userId,
			Verified: false,
		}
		if _, err := identityStore.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: identity}); err != nil {
			return nil, fmt.Errorf("failed to create identity: %w", err)
		}

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
		if _, err := channelStore.SaveChannel(ctx, &accounts.SaveChannelRequest{Channel: channel}); err != nil {
			return nil, fmt.Errorf("failed to create channel: %w", err)
		}

		log.Printf("Created local user %s with identity %s", userId, identityKey)
		return user, nil
	}
}

// NewCredentialsValidator creates a CredentialsValidator from stores.
func NewCredentialsValidator(identityStore accounts.IdentityStore, channelStore accounts.ChannelStore, userStore accounts.UserStore) CredentialsValidator {
	return func(username, password, usernameType string) (accounts.User, error) {
		ctx := context.Background()
		if usernameType == "" {
			usernameType = DetectUsernameType(username)
		}

		if usernameType == "username" {
			return nil, fmt.Errorf("username login not yet implemented - please use email or phone")
		}

		identityKey := accounts.IdentityKey(usernameType, username)

		chResp, err := channelStore.GetChannel(ctx, &accounts.GetChannelRequest{Provider: "local", IdentityKey: identityKey})
		if err != nil {
			bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
			return nil, fmt.Errorf("invalid credentials")
		}
		channel := chResp.Channel

		passwordHash, ok := channel.Credentials["password_hash"].(string)
		if !ok {
			bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
			return nil, fmt.Errorf("invalid credentials")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		idResp, err := identityStore.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: usernameType, IdentityValue: username})
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}

		userResp, err := userStore.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: idResp.Identity.UserID})
		if err != nil {
			return nil, err
		}
		return userResp.User, nil
	}
}

// NewVerifyEmailFunc creates a VerifyEmailFunc from stores.
func NewVerifyEmailFunc(identityStore accounts.IdentityStore, tokenStore VerificationTokenStore) VerifyEmailFunc {
	return func(token string) error {
		ctx := context.Background()
		getResp, err := tokenStore.GetToken(ctx, &GetVerificationTokenRequest{Token: token})
		if err != nil {
			return fmt.Errorf("invalid or expired token")
		}
		verToken := getResp.Token

		if verToken.Type != VerificationTypeEmail {
			return fmt.Errorf("invalid token type")
		}

		if _, err := identityStore.MarkIdentityVerified(ctx, &accounts.MarkIdentityVerifiedRequest{IdentityType: "email", IdentityValue: verToken.Email}); err != nil {
			return fmt.Errorf("failed to verify email: %w", err)
		}

		if _, err := tokenStore.DeleteToken(ctx, &DeleteVerificationTokenRequest{Token: token}); err != nil {
			log.Printf("Warning: failed to delete token: %v", err)
		}

		return nil
	}
}

// NewUpdatePasswordFunc creates an UpdatePasswordFunc from stores.
func NewUpdatePasswordFunc(identityStore accounts.IdentityStore, channelStore accounts.ChannelStore) UpdatePasswordFunc {
	return func(email, newPassword string) error {
		ctx := context.Background()
		idResp, err := identityStore.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: email})
		if err != nil {
			return fmt.Errorf("user not found")
		}
		identity := idResp.Identity

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		identityKey := accounts.IdentityKey("email", email)
		chResp, err := channelStore.GetChannel(ctx, &accounts.GetChannelRequest{Provider: "local", IdentityKey: identityKey})
		var channel *accounts.Channel
		if err != nil || chResp == nil || chResp.Channel == nil {
			channel = &accounts.Channel{
				Provider:    "local",
				IdentityKey: identityKey,
				Credentials: map[string]any{},
				Profile: map[string]any{
					"email": email,
				},
			}
			log.Printf("Creating local channel for user %s (password set via reset)", identity.UserID)
		} else {
			channel = chResp.Channel
		}

		channel.Credentials["password_hash"] = string(passwordHash)
		if _, err := channelStore.SaveChannel(ctx, &accounts.SaveChannelRequest{Channel: channel}); err != nil {
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

// LinkLocalCredentialsConfig groups the stores LinkLocalCredentials needs.
type LinkLocalCredentialsConfig struct {
	UserStore     accounts.UserStore
	IdentityStore accounts.IdentityStore
	ChannelStore  accounts.ChannelStore
	UsernameStore accounts.UsernameStore
}

// LinkLocalCredentials adds local (password) authentication to an existing OAuth-only user.
func LinkLocalCredentials(config LinkLocalCredentialsConfig, userID string, username, password, email string) error {
	ctx := context.Background()
	idResp, err := config.IdentityStore.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: email})
	if err != nil {
		return fmt.Errorf("identity not found: %w", err)
	}
	identity := idResp.Identity
	if identity.UserID != userID {
		return fmt.Errorf("email does not belong to this user")
	}

	identityKey := accounts.IdentityKey("email", email)

	existingResp, err := config.ChannelStore.GetChannel(ctx, &accounts.GetChannelRequest{Provider: "local", IdentityKey: identityKey})
	if err == nil && existingResp != nil && existingResp.Channel != nil {
		return fmt.Errorf("local credentials already exist for this user")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

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

	if _, err := config.ChannelStore.SaveChannel(ctx, &accounts.SaveChannelRequest{Channel: channel}); err != nil {
		return fmt.Errorf("failed to create local channel: %w", err)
	}

	if username != "" && config.UsernameStore != nil {
		if _, err := config.UsernameStore.ReserveUsername(ctx, &accounts.ReserveUsernameRequest{Username: username, UserID: userID}); err != nil {
			log.Printf("Warning: failed to reserve username: %v", err)
		}
	}

	userResp, err := config.UserStore.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: userID})
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	user := userResp.User

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
	if _, err := config.UserStore.SaveUser(ctx, &accounts.SaveUserRequest{User: updatedUser}); err != nil {
		log.Printf("Warning: failed to update user profile: %v", err)
	}

	log.Printf("Linked local credentials to user %s", userID)
	return nil
}

// NewCredentialsValidatorWithUsername creates a CredentialsValidator that supports
// logging in with username (in addition to email/phone).
func NewCredentialsValidatorWithUsername(identityStore accounts.IdentityStore, channelStore accounts.ChannelStore, userStore accounts.UserStore, usernameStore accounts.UsernameStore) CredentialsValidator {
	return func(username, password, usernameType string) (accounts.User, error) {
		ctx := context.Background()
		if usernameType == "" {
			usernameType = DetectUsernameType(username)
		}

		var identityKey string

		if usernameType == "username" {
			if usernameStore == nil {
				return nil, fmt.Errorf("username login not configured")
			}
			userResp, err := usernameStore.GetUserByUsername(ctx, &accounts.GetUserByUsernameRequest{Username: username})
			if err != nil {
				bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
				return nil, fmt.Errorf("invalid credentials")
			}
			userID := userResp.UserID

			idsResp, err := identityStore.GetUserIdentities(ctx, &accounts.GetUserIdentitiesRequest{UserID: userID})
			if err != nil || len(idsResp.Identities) == 0 {
				bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
				return nil, fmt.Errorf("invalid credentials")
			}

			var emailIdentity *accounts.Identity
			for _, id := range idsResp.Identities {
				if id.Type == "email" {
					emailIdentity = id
					break
				}
			}
			if emailIdentity == nil {
				bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
				return nil, fmt.Errorf("invalid credentials")
			}
			identityKey = accounts.IdentityKey("email", emailIdentity.Value)
		} else {
			identityKey = accounts.IdentityKey(usernameType, username)
		}

		chResp, err := channelStore.GetChannel(ctx, &accounts.GetChannelRequest{Provider: "local", IdentityKey: identityKey})
		if err != nil {
			bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
			return nil, fmt.Errorf("invalid credentials")
		}
		channel := chResp.Channel

		passwordHash, ok := channel.Credentials["password_hash"].(string)
		if !ok {
			bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
			return nil, fmt.Errorf("invalid credentials")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		parts := parseIdentityKey(identityKey)
		if parts == nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		idResp, err := identityStore.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: parts[0], IdentityValue: parts[1]})
		if err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		userResp, err := userStore.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: idResp.Identity.UserID})
		if err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}
		return userResp.User, nil
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
