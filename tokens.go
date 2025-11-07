package oneauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// TokenType represents different types of auth tokens
type TokenType string

const (
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypePasswordReset     TokenType = "password_reset"
)

// Default token expiry durations
const (
	TokenExpiryEmailVerification = 24 * time.Hour // 24 hours
	TokenExpiryPasswordReset     = 1 * time.Hour  // 1 hour
)

// AuthToken represents a verification or reset token
type AuthToken struct {
	Token     string    `json:"token"`
	Type      TokenType `json:"type"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenStore interface for managing auth tokens
type TokenStore interface {
	CreateToken(userID, email string, tokenType TokenType, expiryDuration time.Duration) (*AuthToken, error)
	GetToken(token string) (*AuthToken, error)
	DeleteToken(token string) error
	DeleteUserTokens(userID string, tokenType TokenType) error
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// IsExpired checks if a token has expired
func (t *AuthToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid checks if a token is valid (not expired and matches type)
func (t *AuthToken) IsValid(expectedType TokenType) bool {
	return t.Type == expectedType && !t.IsExpired()
}
