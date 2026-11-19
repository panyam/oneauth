//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/panyam/oneauth/outbound"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserTokenModel is the GORM model for outbound.UserTokenRecord. Schema
// notes:
//
//   - Provider and Subject together are the primary key, so the
//     database refuses a second row for one key.
//   - Sealed holds ciphertext from outbound.UserTokens. The store never
//     sees a token.
//   - Version is the compare-and-swap counter. Every write sets it to
//     the expected version plus one.
//
// Auto-migrated alongside the other oneauth tables (see stores.go).
type UserTokenModel struct {
	Provider  string    `gorm:"primaryKey;size:64"`
	Subject   string    `gorm:"primaryKey;size:256"`
	Sealed    []byte    `gorm:"not null"`
	Version   int64     `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

// TableName returns the canonical table name. Pinned so a future GORM
// version cannot rename it.
func (UserTokenModel) TableName() string {
	return "outbound_user_tokens"
}

// UserTokenStore implements outbound.UserTokenStore on GORM. Each write
// is one SQL statement whose WHERE clause or primary key does the
// version check, so compare-and-swap holds across replicas sharing the
// database, on any GORM driver (Postgres, MySQL, SQLite).
type UserTokenStore struct {
	db *gorm.DB
}

// NewUserTokenStore creates a GORM-backed UserTokenStore.
//
// Callers MUST run AutoMigrate (or an equivalent migration) first, so
// the outbound_user_tokens table exists. AutoMigrate in this package
// covers UserTokenModel with the rest of the oneauth tables.
func NewUserTokenStore(db *gorm.DB) *UserTokenStore {
	return &UserTokenStore{db: db}
}

// GetUserToken returns the record, or outbound.ErrUserTokenNotFound
// when no row has the key (gorm.ErrRecordNotFound is mapped to it).
// Other database errors pass through.
func (s *UserTokenStore) GetUserToken(ctx context.Context, req *outbound.GetUserTokenRequest) (*outbound.GetUserTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserToken: req is required")
	}
	var m UserTokenModel
	err := s.db.WithContext(ctx).Where("provider = ? AND subject = ?", req.Provider, req.Subject).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, outbound.ErrUserTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	return &outbound.GetUserTokenResponse{Record: &outbound.UserTokenRecord{
		Provider: m.Provider, Subject: m.Subject, Sealed: m.Sealed, Version: m.Version, UpdatedAt: m.UpdatedAt,
	}}, nil
}

// PutUserToken writes with a version check done by the database:
//
//   - ExpectedVersion 0 inserts with ON CONFLICT DO NOTHING. A row that
//     already exists leaves the insert with no effect, which is
//     outbound.ErrVersionConflict.
//   - Otherwise it updates WHERE version = ExpectedVersion. No row
//     affected means the version moved on or the row was deleted, which
//     is outbound.ErrVersionConflict too, so a refresh can't revive a
//     disconnected token.
//
// Each path is a single statement, so no transaction is needed.
func (s *UserTokenStore) PutUserToken(ctx context.Context, req *outbound.PutUserTokenRequest) (*outbound.PutUserTokenResponse, error) {
	if req == nil || req.Provider == "" || req.Subject == "" {
		return nil, fmt.Errorf("PutUserToken: provider and subject are required")
	}
	now := time.Now()
	next := req.ExpectedVersion + 1
	db := s.db.WithContext(ctx)
	var res *gorm.DB
	if req.ExpectedVersion == 0 {
		res = db.Clauses(clause.OnConflict{DoNothing: true}).Create(&UserTokenModel{
			Provider: req.Provider, Subject: req.Subject, Sealed: req.Sealed, Version: next, UpdatedAt: now,
		})
	} else {
		res = db.Model(&UserTokenModel{}).
			Where("provider = ? AND subject = ? AND version = ?", req.Provider, req.Subject, req.ExpectedVersion).
			Updates(map[string]any{"sealed": req.Sealed, "version": next, "updated_at": now})
	}
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, outbound.ErrVersionConflict
	}
	return &outbound.PutUserTokenResponse{Version: next}, nil
}

// DeleteUserToken removes the row. Deleting a missing row affects
// nothing and is not an error, so disconnecting twice is safe.
func (s *UserTokenStore) DeleteUserToken(ctx context.Context, req *outbound.DeleteUserTokenRequest) (*outbound.DeleteUserTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteUserToken: req is required")
	}
	err := s.db.WithContext(ctx).Where("provider = ? AND subject = ?", req.Provider, req.Subject).Delete(&UserTokenModel{}).Error
	if err != nil {
		return nil, err
	}
	return &outbound.DeleteUserTokenResponse{}, nil
}

var _ outbound.UserTokenStore = (*UserTokenStore)(nil)
