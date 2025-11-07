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

// NewUpdatePasswordFunc creates an UpdatePasswordFunc from stores
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

		// Get local channel
		identityKey := IdentityKey("email", email)
		channel, _, err := channelStore.GetChannel("local", identityKey, false)
		if err != nil {
			return fmt.Errorf("local auth not configured for this user")
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
