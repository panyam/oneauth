//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"errors"
	"time"

	"github.com/panyam/oneauth/core"
	"gorm.io/gorm"
)

// AuthorizationCodeModel is the GORM model for RFC 6749 §4.1
// authorization codes. Schema notes:
//
//   - Code is the primary key (256-bit hex; unique by construction).
//   - ClientID is indexed so a future "revoke all codes for client X"
//     operation (if needed) stays cheap.
//   - ExpiresAt is indexed so CleanupExpired's range scan stays
//     O(log n) as the table grows.
//   - Scopes + AuthorizationDetails use gorm:"serializer:json" — the
//     same portable pattern AppStore + DeviceAuthorization use for
//     their slice / struct-slice fields.
//
// Auto-migrated alongside the other oneauth tables (see stores.go).
type AuthorizationCodeModel struct {
	Code                 string                     `gorm:"primaryKey;size:128"`
	ClientID             string                     `gorm:"size:128;not null;index"`
	RedirectURI          string                     `gorm:"size:1024;not null"`
	Scopes               []string                   `gorm:"serializer:json"`
	Subject              string                     `gorm:"size:256;not null"`
	CodeChallenge        string                     `gorm:"size:256"`
	CodeChallengeMethod  string                     `gorm:"size:16"`
	AuthorizationDetails []core.AuthorizationDetail `gorm:"serializer:json"`
	IssuedAt             time.Time                  `gorm:"autoCreateTime"`
	ExpiresAt            time.Time                  `gorm:"not null;index"`
}

// TableName returns the canonical table name. Pinned so a future GORM
// version cannot silently rename it under us.
func (AuthorizationCodeModel) TableName() string {
	return "authorization_codes"
}

// AuthorizationCodeStore implements core.AuthorizationCodeStore on
// GORM. Production-grade backend for the RFC 6749 §4.1 code flow —
// multi-node compatible (database is the shared source of truth) and
// works against any GORM-supported driver (Postgres / MySQL / SQLite).
type AuthorizationCodeStore struct {
	db *gorm.DB
}

// NewAuthorizationCodeStore creates a GORM-backed
// AuthorizationCodeStore.
//
// Callers MUST run AutoMigrate (or equivalent migration) before use to
// ensure the authorization_codes table exists. AutoMigrate in this
// package covers AuthorizationCodeModel along with the rest of the
// oneauth tables.
func NewAuthorizationCodeStore(db *gorm.DB) *AuthorizationCodeStore {
	return &AuthorizationCodeStore{db: db}
}

// CreateAuthorizationCode inserts a new authorization code. Empty
// code is rejected; collisions return a generic error matching
// InMemoryAuthorizationCodeStore semantics (the caller already drew
// from CSPRNG; a collision is a programmer error, not a typed
// condition).
func (s *AuthorizationCodeStore) CreateAuthorizationCode(ctx context.Context, req *core.CreateAuthorizationCodeRequest) (*core.CreateAuthorizationCodeResponse, error) {
	if req == nil || req.Code == nil {
		return nil, errors.New("CreateAuthorizationCode: code is required")
	}
	c := req.Code
	if c.Code == "" {
		return nil, errors.New("CreateAuthorizationCode: code value is required")
	}

	// Pre-check the uniqueness constraint so we surface the same
	// error message the in-memory store uses, regardless of which
	// driver's constraint error surfaces first. Cheap because the
	// lookup hits the primary key.
	var existing int64
	if err := s.db.WithContext(ctx).Model(&AuthorizationCodeModel{}).
		Where("code = ?", c.Code).Count(&existing).Error; err != nil {
		return nil, err
	}
	if existing > 0 {
		return nil, errors.New("CreateAuthorizationCode: code collision")
	}

	if err := s.db.WithContext(ctx).Create(authCodeToModel(c)).Error; err != nil {
		return nil, err
	}
	return &core.CreateAuthorizationCodeResponse{}, nil
}

// GetAuthorizationCode returns the binding for the given code, or
// ErrAuthorizationCodeNotFound. Does NOT filter by expiry — the
// caller (the token endpoint redemption handler) checks IsExpired so
// it can surface a distinct invalid_grant vs expired error.
func (s *AuthorizationCodeStore) GetAuthorizationCode(ctx context.Context, req *core.GetAuthorizationCodeRequest) (*core.GetAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	var model AuthorizationCodeModel
	if err := s.db.WithContext(ctx).First(&model, "code = ?", req.Code).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrAuthorizationCodeNotFound
		}
		return nil, err
	}
	return &core.GetAuthorizationCodeResponse{Code: modelToAuthCode(&model)}, nil
}

// DeleteAuthorizationCode removes the binding. Used by the token
// endpoint on successful exchange (prevents replay) and by callers
// cleaning up rejected flows. Returns ErrAuthorizationCodeNotFound
// when no record matches — the redemption handler relies on this so a
// second delete returns the sentinel (already consumed) rather than a
// generic error.
func (s *AuthorizationCodeStore) DeleteAuthorizationCode(ctx context.Context, req *core.DeleteAuthorizationCodeRequest) (*core.DeleteAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	result := s.db.WithContext(ctx).Delete(&AuthorizationCodeModel{}, "code = ?", req.Code)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	return &core.DeleteAuthorizationCodeResponse{}, nil
}

// CleanupExpired enumerates the store and removes every record whose
// ExpiresAt is at or before the current wall-clock time. The
// ExpiresAt index keeps the scan O(log n + k) for k expired rows.
func (s *AuthorizationCodeStore) CleanupExpired(ctx context.Context, _ *core.CleanupExpiredAuthorizationCodesRequest) (*core.CleanupExpiredAuthorizationCodesResponse, error) {
	now := time.Now()
	result := s.db.WithContext(ctx).Delete(&AuthorizationCodeModel{}, "expires_at <= ?", now)
	if result.Error != nil {
		return nil, result.Error
	}
	return &core.CleanupExpiredAuthorizationCodesResponse{Removed: int(result.RowsAffected)}, nil
}

// authCodeToModel maps the public struct onto the GORM model.
func authCodeToModel(c *core.AuthorizationCode) *AuthorizationCodeModel {
	return &AuthorizationCodeModel{
		Code:                 c.Code,
		ClientID:             c.ClientID,
		RedirectURI:          c.RedirectURI,
		Scopes:               c.Scopes,
		Subject:              c.Subject,
		CodeChallenge:        c.CodeChallenge,
		CodeChallengeMethod:  c.CodeChallengeMethod,
		AuthorizationDetails: c.AuthorizationDetails,
		IssuedAt:             c.IssuedAt,
		ExpiresAt:            c.ExpiresAt,
	}
}

// modelToAuthCode maps the GORM model back to the public struct.
func modelToAuthCode(m *AuthorizationCodeModel) *core.AuthorizationCode {
	return &core.AuthorizationCode{
		Code:                 m.Code,
		ClientID:             m.ClientID,
		RedirectURI:          m.RedirectURI,
		Scopes:               m.Scopes,
		Subject:              m.Subject,
		CodeChallenge:        m.CodeChallenge,
		CodeChallengeMethod:  m.CodeChallengeMethod,
		AuthorizationDetails: m.AuthorizationDetails,
		IssuedAt:             m.IssuedAt,
		ExpiresAt:            m.ExpiresAt,
	}
}
