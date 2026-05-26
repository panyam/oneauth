package localauth

import "time"

// VerificationType is the kind of email/phone-mediated verification token
// issued by localauth (e.g. signup email-verify, password-reset).
//
// Renamed from the previous core.TokenType to avoid colliding with OAuth
// access/refresh-token semantics that live in apiauth/core.
type VerificationType string

const (
	// String values kept stable for backwards-compatible persisted data
	// across the rename.
	VerificationTypeEmail         VerificationType = "email_verification"
	VerificationTypePasswordReset VerificationType = "password_reset"
)

// Default verification token expiry durations.
const (
	VerificationExpiryEmail         = 24 * time.Hour
	VerificationExpiryPasswordReset = 1 * time.Hour
)

// VerificationToken represents a short-lived email-mediated token used by
// localauth flows (email verification, password reset).
//
// Renamed from the previous core.AuthToken so the type name reflects its
// role and doesn't collide with OAuth access/refresh tokens.
type VerificationToken struct {
	Token     string           `json:"token"`
	Type      VerificationType `json:"type"`
	Subject   string           `json:"subject"`
	Email     string           `json:"email"`
	CreatedAt time.Time        `json:"created_at"`
	ExpiresAt time.Time        `json:"expires_at"`
}

// IsExpired checks if a verification token has expired.
func (t *VerificationToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid checks if a token is valid (not expired and matches type).
func (t *VerificationToken) IsValid(expectedType VerificationType) bool {
	return t.Type == expectedType && !t.IsExpired()
}

// VerificationTokenStore manages localauth verification tokens (signup
// email-verify, password-reset). Renamed from core.TokenStore.
type VerificationTokenStore interface {
	CreateToken(subject, email string, tokenType VerificationType, expiryDuration time.Duration) (*VerificationToken, error)
	GetToken(token string) (*VerificationToken, error)
	DeleteToken(token string) error
	DeleteSubjectTokens(subject string, tokenType VerificationType) error
}
