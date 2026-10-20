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
//   - UsedAt and IssuedTokenExpiresAt are nullable: NULL means unused,
//     or no token recorded yet. A used row is kept until the access
//     token it produced expires (RFC 6749 §4.1.2 reuse revocation).
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
	DPoPJKT              string                     `gorm:"size:64"` // RFC 9449 §10 dpop_jkt; empty = code not key-bound
	AuthorizationDetails []core.AuthorizationDetail `gorm:"serializer:json"`
	Nonce                string                     `gorm:"size:512"` // OIDC nonce, echoed into the ID token
	AuthTime             *time.Time                 // OIDC auth_time; NULL when unknown
	IssuedAt             time.Time                  `gorm:"autoCreateTime"`
	ExpiresAt            time.Time                  `gorm:"not null;index"`
	UsedAt               *time.Time
	IssuedTokenID        string     `gorm:"size:128"`
	IssuedTokenExpiresAt *time.Time `gorm:"index"`
	IssuedRefreshFamily  string     `gorm:"size:128"`
	ReuseDetected        bool       `gorm:"not null;default:false"`
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

// ConsumeAuthorizationCode marks an unused code used. The conditional
// UPDATE (`used_at IS NULL`) is the single-use gate, so of two
// concurrent calls exactly one sees a row affected. The loser sets
// reuse_detected and reads the row in one transaction; the UPDATE takes
// the row lock first, so the read sees any tokens a racing
// RecordAuthorizationCodeTokens has committed. Returns
// core.ErrAuthorizationCodeUsed with the record for a used code, and
// core.ErrAuthorizationCodeNotFound for a missing one.
func (s *AuthorizationCodeStore) ConsumeAuthorizationCode(ctx context.Context, req *core.ConsumeAuthorizationCodeRequest) (*core.ConsumeAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	var model AuthorizationCodeModel
	used := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		res := tx.Model(&AuthorizationCodeModel{}).Where("code = ? AND used_at IS NULL", req.Code).Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 1 {
			if err := tx.First(&model, "code = ?", req.Code).Error; err != nil {
				return err
			}
			model.UsedAt = nil
			return nil
		}
		used = true
		if err := tx.Model(&AuthorizationCodeModel{}).Where("code = ?", req.Code).Update("reuse_detected", true).Error; err != nil {
			return err
		}
		return tx.First(&model, "code = ?", req.Code).Error
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrAuthorizationCodeNotFound
		}
		return nil, err
	}
	resp := &core.ConsumeAuthorizationCodeResponse{Code: modelToAuthCode(&model)}
	if used {
		return resp, core.ErrAuthorizationCodeUsed
	}
	return resp, nil
}

// RecordAuthorizationCodeTokens stores the tokens a redemption minted
// and reads reuse_detected in the same transaction, after the UPDATE
// has taken the row lock, so a racing ConsumeAuthorizationCode either
// sees these tokens or has set the flag this read returns. Returns
// core.ErrAuthorizationCodeNotFound for a missing code.
func (s *AuthorizationCodeStore) RecordAuthorizationCodeTokens(ctx context.Context, req *core.RecordAuthorizationCodeTokensRequest) (*core.RecordAuthorizationCodeTokensResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	var model AuthorizationCodeModel
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&AuthorizationCodeModel{}).Where("code = ?", req.Code).Updates(map[string]any{
			"issued_token_id":         req.TokenID,
			"issued_token_expires_at": nullableTime(req.TokenExpiresAt),
			"issued_refresh_family":   req.RefreshFamily,
		}).Error; err != nil {
			return err
		}
		return tx.First(&model, "code = ?", req.Code).Error
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrAuthorizationCodeNotFound
		}
		return nil, err
	}
	return &core.RecordAuthorizationCodeTokensResponse{ReuseDetected: model.ReuseDetected}, nil
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

// CleanupExpired removes every record past its RetainUntil: the code's
// own expiry, or for a used code with a recorded token, the later
// expiry of that token. The ExpiresAt index keeps the scan
// O(log n + k) for k expired rows.
func (s *AuthorizationCodeStore) CleanupExpired(ctx context.Context, _ *core.CleanupExpiredAuthorizationCodesRequest) (*core.CleanupExpiredAuthorizationCodesResponse, error) {
	now := time.Now()
	result := s.db.WithContext(ctx).Delete(&AuthorizationCodeModel{},
		"expires_at <= ? AND (used_at IS NULL OR issued_token_expires_at IS NULL OR issued_token_expires_at <= ?)", now, now)
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
		DPoPJKT:              c.DPoPJKT,
		AuthorizationDetails: c.AuthorizationDetails,
		Nonce:                c.Nonce,
		AuthTime:             nullableTime(c.AuthTime),
		IssuedAt:             c.IssuedAt,
		ExpiresAt:            c.ExpiresAt,
		UsedAt:               nullableTime(c.UsedAt),
		IssuedTokenID:        c.IssuedTokenID,
		IssuedTokenExpiresAt: nullableTime(c.IssuedTokenExpiresAt),
		IssuedRefreshFamily:  c.IssuedRefreshFamily,
		ReuseDetected:        c.ReuseDetected,
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
		DPoPJKT:              m.DPoPJKT,
		AuthorizationDetails: m.AuthorizationDetails,
		Nonce:                m.Nonce,
		AuthTime:             derefTime(m.AuthTime),
		IssuedAt:             m.IssuedAt,
		ExpiresAt:            m.ExpiresAt,
		UsedAt:               derefTime(m.UsedAt),
		IssuedTokenID:        m.IssuedTokenID,
		IssuedTokenExpiresAt: derefTime(m.IssuedTokenExpiresAt),
		IssuedRefreshFamily:  m.IssuedRefreshFamily,
		ReuseDetected:        m.ReuseDetected,
	}
}

// nullableTime maps the zero time to NULL.
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// derefTime maps NULL to the zero time.
func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
