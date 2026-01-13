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
	TokenTypeRefresh           TokenType = "refresh"
)

// Default token expiry durations
const (
	TokenExpiryEmailVerification = 24 * time.Hour     // 24 hours
	TokenExpiryPasswordReset     = 1 * time.Hour      // 1 hour
	TokenExpiryAccessToken       = 15 * time.Minute   // 15 minutes
	TokenExpiryRefreshToken      = 7 * 24 * time.Hour // 7 days
)

// Common errors for token operations
var (
	ErrTokenNotFound  = fmt.Errorf("token not found")
	ErrTokenExpired   = fmt.Errorf("token expired")
	ErrTokenRevoked   = fmt.Errorf("token revoked")
	ErrTokenReused    = fmt.Errorf("token reuse detected")
	ErrInvalidGrant   = fmt.Errorf("invalid grant")
	ErrInvalidScope   = fmt.Errorf("invalid scope")
	ErrAPIKeyNotFound = fmt.Errorf("api key not found")
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

// RefreshToken represents a long-lived refresh token for API access
type RefreshToken struct {
	Token      string         `json:"token"`       // 64-char hex token value
	TokenHash  string         `json:"token_hash"`  // SHA256 hash for storage (optional)
	UserID     string         `json:"user_id"`     // Associated user
	ClientID   string         `json:"client_id"`   // Optional client/app identifier
	DeviceInfo map[string]any `json:"device_info"` // User agent, IP, etc.
	Family     string         `json:"family"`      // Token family for rotation tracking
	Generation int            `json:"generation"`  // Increments on rotation
	Scopes     []string       `json:"scopes"`      // Granted scopes
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	LastUsedAt time.Time      `json:"last_used_at"`
	RevokedAt  *time.Time     `json:"revoked_at,omitempty"`
	Revoked    bool           `json:"revoked"`
}

// IsExpired checks if a refresh token has expired
func (t *RefreshToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid checks if a refresh token is valid (not expired and not revoked)
func (t *RefreshToken) IsValid() bool {
	return !t.Revoked && !t.IsExpired()
}

// APIKey represents a long-lived API key for programmatic access
type APIKey struct {
	KeyID      string     `json:"key_id"`      // Public identifier (e.g., "oa_abc123...")
	KeyHash    string     `json:"key_hash"`    // bcrypt hash of the secret portion
	UserID     string     `json:"user_id"`     // Owner of this key
	Name       string     `json:"name"`        // User-defined label
	Scopes     []string   `json:"scopes"`      // Allowed scopes
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"` // Optional expiry
	LastUsedAt time.Time  `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Revoked    bool       `json:"revoked"`
}

// IsExpired checks if an API key has expired
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false // No expiry set
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsValid checks if an API key is valid (not expired and not revoked)
func (k *APIKey) IsValid() bool {
	return !k.Revoked && !k.IsExpired()
}

// TokenPair represents the response from a successful authentication
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`     // "Bearer"
	ExpiresIn    int64  `json:"expires_in"`     // Seconds until access token expires
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenRequest represents a request to the token endpoint
type TokenRequest struct {
	GrantType    string `json:"grant_type"`              // "password", "refresh_token"
	Username     string `json:"username,omitempty"`      // For password grant
	Password     string `json:"password,omitempty"`      // For password grant
	RefreshToken string `json:"refresh_token,omitempty"` // For refresh_token grant
	Scope        string `json:"scope,omitempty"`         // Requested scopes
	ClientID     string `json:"client_id,omitempty"`     // Optional client identifier
}

// TokenError represents an OAuth 2.0 compliant error response
type TokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// GenerateAPIKeyID generates a new API key ID with prefix
func GenerateAPIKeyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate key ID: %w", err)
	}
	return "oa_" + hex.EncodeToString(b), nil
}

// GenerateAPIKeySecret generates the secret portion of an API key
func GenerateAPIKeySecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate key secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}
