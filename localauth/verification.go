package localauth

import (
	"context"
	"time"
)

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

// CreateVerificationTokenRequest carries the inputs for issuing a verification
// token. Subject may be empty for password-reset flows where the AS does not
// want to reveal whether the email belongs to a registered user.
type CreateVerificationTokenRequest struct {
	Subject        string
	Email          string
	Type           VerificationType
	ExpiryDuration time.Duration
}

type CreateVerificationTokenResponse struct {
	Token *VerificationToken
}

type GetVerificationTokenRequest struct {
	Token string
}

type GetVerificationTokenResponse struct {
	Token *VerificationToken
}

type DeleteVerificationTokenRequest struct {
	Token string
}

type DeleteVerificationTokenResponse struct{}

type DeleteSubjectVerificationTokensRequest struct {
	Subject string
	Type    VerificationType
}

type DeleteSubjectVerificationTokensResponse struct{}

// VerificationTokenStore manages localauth verification tokens (signup
// email-verify, password-reset). Renamed from core.TokenStore.
type VerificationTokenStore interface {
	CreateToken(ctx context.Context, req *CreateVerificationTokenRequest) (*CreateVerificationTokenResponse, error)
	GetToken(ctx context.Context, req *GetVerificationTokenRequest) (*GetVerificationTokenResponse, error)
	DeleteToken(ctx context.Context, req *DeleteVerificationTokenRequest) (*DeleteVerificationTokenResponse, error)
	DeleteSubjectTokens(ctx context.Context, req *DeleteSubjectVerificationTokensRequest) (*DeleteSubjectVerificationTokensResponse, error)
}
