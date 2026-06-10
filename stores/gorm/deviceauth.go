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

// DeviceAuthorizationModel is the GORM model for RFC 8628 device
// authorization records. Schema notes:
//
//   - DeviceCode is the primary key (256-bit hex; unique by construction).
//   - UserCodeUpper is the normalized form (upper-case, dashes/spaces
//     stripped) and carries the only index for the user_code lookup
//     path. Storing a denormalized column instead of a functional index
//     keeps the schema portable across SQLite / Postgres / MySQL —
//     functional indexes differ in syntax per driver. The original
//     UserCode column preserves the display form (XXXX-XXXX) the device
//     showed the user.
//   - ExpiresAt is indexed so CleanupExpired's range scan stays O(log n)
//     as the table grows.
//   - LastPolledAt is *time.Time (nullable) so a never-polled record
//     doesn't carry the zero-value sentinel through the DB.
//   - Scopes uses gorm:"serializer:json" — the same portable pattern
//     AppStore uses for its slice fields.
//
// Auto-migrated alongside the other oneauth tables (see stores.go).
type DeviceAuthorizationModel struct {
	DeviceCode        string    `gorm:"primaryKey;size:128"`
	UserCode          string    `gorm:"size:32;not null"`
	UserCodeUpper     string    `gorm:"size:32;not null;index"`
	ClientID          string    `gorm:"size:128;not null;index"`
	Scopes            []string  `gorm:"serializer:json"`
	RequestedAudience string    `gorm:"size:512"`
	Status            string    `gorm:"size:16;not null"`
	ApprovedSubject   string    `gorm:"size:256"`
	CreatedAt         time.Time `gorm:"autoCreateTime"`
	ExpiresAt         time.Time `gorm:"not null;index"`
	LastPolledAt      *time.Time
	IntervalSeconds   int `gorm:"not null"`
}

// TableName returns the canonical table name. Pinned so a future GORM
// version cannot silently rename it under us.
func (DeviceAuthorizationModel) TableName() string {
	return "device_authorizations"
}

// DeviceAuthStore implements core.DeviceAuthorizationStore on GORM.
// Production-grade backend for the RFC 8628 device flow (issue 269) —
// multi-node compatible (database is the shared source of truth) and
// works against any GORM-supported driver (Postgres / MySQL / SQLite).
type DeviceAuthStore struct {
	db *gorm.DB
}

// NewDeviceAuthStore creates a GORM-backed DeviceAuthorizationStore.
//
// Callers MUST run AutoMigrate (or equivalent migration) before use to
// ensure the device_authorizations table exists. AutoMigrate in this
// package covers DeviceAuthorizationModel along with the rest of the
// oneauth tables.
func NewDeviceAuthStore(db *gorm.DB) *DeviceAuthStore {
	return &DeviceAuthStore{db: db}
}

// CreateDeviceAuthorization inserts a new device authorization. Empty
// device_code or user_code is rejected; collisions on either return a
// generic error matching InMemoryDeviceAuthorizationStore semantics
// (the caller already drew from CSPRNG; a collision is a programmer
// error, not a typed condition).
func (s *DeviceAuthStore) CreateDeviceAuthorization(ctx context.Context, req *core.CreateDeviceAuthorizationRequest) (*core.CreateDeviceAuthorizationResponse, error) {
	if req == nil || req.Authorization == nil {
		return nil, errors.New("CreateDeviceAuthorization: authorization is required")
	}
	a := req.Authorization
	if a.DeviceCode == "" || a.UserCode == "" {
		return nil, errors.New("CreateDeviceAuthorization: device_code and user_code are required")
	}
	upper := core.UpperUserCode(a.UserCode)

	// Pre-check both uniqueness constraints so we surface the same error
	// message the in-memory store uses, regardless of which driver's
	// constraint error surfaces first. Cheap because both lookups hit
	// indexes and the table is small in practice.
	var existingDC int64
	if err := s.db.WithContext(ctx).Model(&DeviceAuthorizationModel{}).
		Where("device_code = ?", a.DeviceCode).Count(&existingDC).Error; err != nil {
		return nil, err
	}
	if existingDC > 0 {
		return nil, errors.New("CreateDeviceAuthorization: device_code collision")
	}
	var existingUC int64
	if err := s.db.WithContext(ctx).Model(&DeviceAuthorizationModel{}).
		Where("user_code_upper = ?", upper).Count(&existingUC).Error; err != nil {
		return nil, err
	}
	if existingUC > 0 {
		return nil, errors.New("CreateDeviceAuthorization: user_code collision")
	}

	model := deviceAuthToModel(a)
	model.UserCodeUpper = upper
	if err := s.db.WithContext(ctx).Create(model).Error; err != nil {
		return nil, err
	}
	return &core.CreateDeviceAuthorizationResponse{}, nil
}

// GetByDeviceCode returns the authorization for the given device_code,
// or ErrDeviceAuthorizationNotFound. Does NOT filter by status or
// expiry — the caller (the token endpoint handler) checks both. Matches
// InMemoryDeviceAuthorizationStore contract.
func (s *DeviceAuthStore) GetByDeviceCode(ctx context.Context, req *core.GetByDeviceCodeRequest) (*core.GetByDeviceCodeResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	var model DeviceAuthorizationModel
	if err := s.db.WithContext(ctx).First(&model, "device_code = ?", req.DeviceCode).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, err
	}
	return &core.GetByDeviceCodeResponse{Authorization: modelToDeviceAuth(&model)}, nil
}

// GetByUserCode returns the authorization for the given user_code
// (case- and dash-insensitive comparison), or
// ErrDeviceAuthorizationNotFound.
func (s *DeviceAuthStore) GetByUserCode(ctx context.Context, req *core.GetByUserCodeRequest) (*core.GetByUserCodeResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	var model DeviceAuthorizationModel
	if err := s.db.WithContext(ctx).First(&model, "user_code_upper = ?", core.UpperUserCode(req.UserCode)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, err
	}
	return &core.GetByUserCodeResponse{Authorization: modelToDeviceAuth(&model)}, nil
}

// ApproveDeviceAuthorization transitions a pending authorization to
// approved and binds the subject + scopes. Returns
// ErrDeviceAuthorizationNotFound when no pending record matches
// user_code (already approved, already denied, expired-and-cleaned,
// or never existed all look identical — no info leak).
func (s *DeviceAuthStore) ApproveDeviceAuthorization(ctx context.Context, req *core.ApproveDeviceAuthorizationRequest) (*core.ApproveDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	upper := core.UpperUserCode(req.UserCode)

	var model DeviceAuthorizationModel
	tx := s.db.WithContext(ctx).Where(
		"user_code_upper = ? AND status = ?",
		upper, string(core.DeviceAuthorizationStatusPending),
	).First(&model)
	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, tx.Error
	}
	model.Status = string(core.DeviceAuthorizationStatusApproved)
	model.ApprovedSubject = req.ApprovedSubject
	if req.GrantedScopes != nil {
		model.Scopes = req.GrantedScopes
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return nil, err
	}
	return &core.ApproveDeviceAuthorizationResponse{Authorization: modelToDeviceAuth(&model)}, nil
}

// DenyDeviceAuthorization transitions a pending authorization to
// denied. Returns ErrDeviceAuthorizationNotFound when no pending
// record matches user_code.
func (s *DeviceAuthStore) DenyDeviceAuthorization(ctx context.Context, req *core.DenyDeviceAuthorizationRequest) (*core.DenyDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	upper := core.UpperUserCode(req.UserCode)

	result := s.db.WithContext(ctx).Model(&DeviceAuthorizationModel{}).
		Where("user_code_upper = ? AND status = ?", upper, string(core.DeviceAuthorizationStatusPending)).
		Update("status", string(core.DeviceAuthorizationStatusDenied))
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	return &core.DenyDeviceAuthorizationResponse{}, nil
}

// UpdatePollingState records a poll attempt. Always updates
// LastPolledAt; raises IntervalSeconds by 5 when SlowDown is true
// (RFC 8628 §3.5).
func (s *DeviceAuthStore) UpdatePollingState(ctx context.Context, req *core.UpdatePollingStateRequest) (*core.UpdatePollingStateResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	var model DeviceAuthorizationModel
	if err := s.db.WithContext(ctx).First(&model, "device_code = ?", req.DeviceCode).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, err
	}
	polled := req.PolledAt
	model.LastPolledAt = &polled
	if req.SlowDown {
		model.IntervalSeconds += 5
	}
	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return nil, err
	}
	return &core.UpdatePollingStateResponse{Authorization: modelToDeviceAuth(&model)}, nil
}

// DeleteDeviceAuthorization removes the authorization. Used by the
// token endpoint on successful exchange (prevents replay) and by
// callers cleaning up rejected flows. Returns
// ErrDeviceAuthorizationNotFound when no record matches.
func (s *DeviceAuthStore) DeleteDeviceAuthorization(ctx context.Context, req *core.DeleteDeviceAuthorizationRequest) (*core.DeleteDeviceAuthorizationResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	result := s.db.WithContext(ctx).Delete(&DeviceAuthorizationModel{}, "device_code = ?", req.DeviceCode)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	return &core.DeleteDeviceAuthorizationResponse{}, nil
}

// CleanupExpired enumerates the store and removes every record whose
// ExpiresAt is at or before the current wall-clock time. The
// ExpiresAt index keeps the scan O(log n + k) for k expired rows.
func (s *DeviceAuthStore) CleanupExpired(ctx context.Context, _ *core.CleanupExpiredDeviceAuthsRequest) (*core.CleanupExpiredDeviceAuthsResponse, error) {
	now := time.Now()
	result := s.db.WithContext(ctx).Delete(&DeviceAuthorizationModel{}, "expires_at <= ?", now)
	if result.Error != nil {
		return nil, result.Error
	}
	return &core.CleanupExpiredDeviceAuthsResponse{Removed: int(result.RowsAffected)}, nil
}

// deviceAuthToModel maps the public struct onto the GORM model.
// UserCodeUpper is populated by the caller (CreateDeviceAuthorization)
// so the normalization rule lives in one place.
func deviceAuthToModel(a *core.DeviceAuthorization) *DeviceAuthorizationModel {
	model := &DeviceAuthorizationModel{
		DeviceCode:        a.DeviceCode,
		UserCode:          a.UserCode,
		ClientID:          a.ClientID,
		Scopes:            a.Scopes,
		RequestedAudience: a.RequestedAudience,
		Status:            string(a.Status),
		ApprovedSubject:   a.ApprovedSubject,
		CreatedAt:         a.CreatedAt,
		ExpiresAt:         a.ExpiresAt,
		IntervalSeconds:   a.IntervalSeconds,
	}
	if !a.LastPolledAt.IsZero() {
		t := a.LastPolledAt
		model.LastPolledAt = &t
	}
	return model
}

// modelToDeviceAuth maps the GORM model back to the public struct.
// A nullable LastPolledAt becomes the zero time, matching the
// InMemoryDeviceAuthorizationStore contract.
func modelToDeviceAuth(m *DeviceAuthorizationModel) *core.DeviceAuthorization {
	out := &core.DeviceAuthorization{
		DeviceCode:        m.DeviceCode,
		UserCode:          m.UserCode,
		ClientID:          m.ClientID,
		Scopes:            m.Scopes,
		RequestedAudience: m.RequestedAudience,
		Status:            core.DeviceAuthorizationStatus(m.Status),
		ApprovedSubject:   m.ApprovedSubject,
		CreatedAt:         m.CreatedAt,
		ExpiresAt:         m.ExpiresAt,
		IntervalSeconds:   m.IntervalSeconds,
	}
	if m.LastPolledAt != nil {
		out.LastPolledAt = *m.LastPolledAt
	}
	return out
}

