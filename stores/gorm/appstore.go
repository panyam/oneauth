//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"time"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
	"gorm.io/gorm"
)

// AppRegistrationModel is the GORM model for app registrations. Slice fields
// are JSON-encoded on the database side via the gorm:"serializer:json" tag —
// works identically across SQLite, MySQL, Postgres without DB-specific JSONB
// quirks. Auto-migrated alongside the other oneauth tables.
type AppRegistrationModel struct {
	ClientID                  string                     `gorm:"primaryKey;size:128"`
	ClientDomain              string                     `gorm:"size:256"`
	SigningAlg                string                     `gorm:"size:16;not null"`
	MaxRooms                  int                        `gorm:"not null;default:0"`
	MaxMsgRate                float64                    `gorm:"not null;default:0"`
	AuthorizationDetailsTypes []string                   `gorm:"serializer:json"` // RFC 9396
	CreatedAt                 time.Time                  `gorm:"autoCreateTime"`
	UpdatedAt                 time.Time                  `gorm:"autoUpdateTime"`
	Revoked                   bool                       `gorm:"not null;default:false"`

	// RFC 7591 / 7592 client metadata (issue 168 / 169 / 172).
	ClientName              string   `gorm:"size:256"`
	ClientURI               string   `gorm:"size:256"`
	RedirectURIs            []string `gorm:"serializer:json"`
	GrantTypes              []string `gorm:"serializer:json"`
	Scope                   string   `gorm:"size:512"`
	TokenEndpointAuthMethod string   `gorm:"size:64"`

	// RFC 7592 §3 management credentials (issue 168). Persisted so the
	// management endpoints can authenticate subsequent requests after restart.
	RegistrationAccessToken string `gorm:"size:256"`
	RegistrationClientURI   string `gorm:"size:512"`
}

func (AppRegistrationModel) TableName() string {
	return "app_registrations"
}

// AppStore implements admin.AppRegistrationStore on GORM. Production-grade
// backend for the persistence chain started in 165 — multi-node compatible
// (database is the shared source-of-truth) and works against any GORM-supported
// driver (Postgres / MySQL / SQLite).
type AppStore struct {
	db *gorm.DB
}

// NewAppStore creates a GORM-backed AppRegistrationStore.
//
// Callers MUST run AutoMigrate (or equivalent migration) before use to
// ensure the app_registrations table exists. AutoMigrate in this package
// covers AppRegistrationModel along with the rest of the oneauth tables.
func NewAppStore(db *gorm.DB) *AppStore {
	return &AppStore{db: db}
}

// SaveApp inserts or replaces the registration for req.App.ClientID. Empty
// client_id is rejected with the same error pattern as InMemoryAppStore.
func (s *AppStore) SaveApp(ctx context.Context, req *admin.SaveAppRequest) (*admin.SaveAppResponse, error) {
	if req == nil || req.App == nil || req.App.ClientID == "" {
		return nil, errClientIDRequired
	}
	model := appRegistrationToModel(req.App)
	if err := s.db.WithContext(ctx).Save(model).Error; err != nil {
		return nil, err
	}
	return &admin.SaveAppResponse{}, nil
}

// GetApp returns the registration for req.ClientID, or admin.ErrAppNotFound.
func (s *AppStore) GetApp(ctx context.Context, req *admin.GetAppRequest) (*admin.GetAppResponse, error) {
	if req == nil {
		return nil, errClientIDRequired
	}
	var model AppRegistrationModel
	if err := s.db.WithContext(ctx).First(&model, "client_id = ?", req.ClientID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, admin.ErrAppNotFound
		}
		return nil, err
	}
	return &admin.GetAppResponse{App: modelToAppRegistration(&model)}, nil
}

// ListApps returns every registration in the store. Order is unspecified.
func (s *AppStore) ListApps(ctx context.Context, req *admin.ListAppsRequest) (*admin.ListAppsResponse, error) {
	var models []AppRegistrationModel
	if err := s.db.WithContext(ctx).Find(&models).Error; err != nil {
		return nil, err
	}
	out := make([]*admin.AppRegistration, len(models))
	for i := range models {
		out[i] = modelToAppRegistration(&models[i])
	}
	return &admin.ListAppsResponse{Apps: out}, nil
}

// DeleteApp removes the registration for req.ClientID. Returns admin.ErrAppNotFound
// if no such registration exists, matching InMemoryAppStore semantics.
func (s *AppStore) DeleteApp(ctx context.Context, req *admin.DeleteAppRequest) (*admin.DeleteAppResponse, error) {
	if req == nil {
		return nil, errClientIDRequired
	}
	result := s.db.WithContext(ctx).Delete(&AppRegistrationModel{}, "client_id = ?", req.ClientID)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, admin.ErrAppNotFound
	}
	return &admin.DeleteAppResponse{}, nil
}

// errClientIDRequired matches the InMemoryAppStore error message so the
// shared appstoretest contract suite passes uniformly across backends.
var errClientIDRequired = &appStoreError{"AppRegistration.ClientID required"}

type appStoreError struct{ msg string }

func (e *appStoreError) Error() string { return e.msg }

func appRegistrationToModel(app *admin.AppRegistration) *AppRegistrationModel {
	return &AppRegistrationModel{
		ClientID:                  app.ClientID,
		ClientDomain:              app.ClientDomain,
		SigningAlg:                app.SigningAlg,
		MaxRooms:                  app.MaxRooms,
		MaxMsgRate:                app.MaxMsgRate,
		AuthorizationDetailsTypes: app.AuthorizationDetailsTypes,
		CreatedAt:                 app.CreatedAt,
		Revoked:                   app.Revoked,
		ClientName:                app.ClientName,
		ClientURI:                 app.ClientURI,
		RedirectURIs:              app.RedirectURIs,
		GrantTypes:                app.GrantTypes,
		Scope:                     app.Scope,
		TokenEndpointAuthMethod:   app.TokenEndpointAuthMethod,
		RegistrationAccessToken:   app.RegistrationAccessToken,
		RegistrationClientURI:     app.RegistrationClientURI,
	}
}

func modelToAppRegistration(m *AppRegistrationModel) *admin.AppRegistration {
	return &admin.AppRegistration{
		ClientID:                  m.ClientID,
		ClientDomain:              m.ClientDomain,
		SigningAlg:                m.SigningAlg,
		MaxRooms:                  m.MaxRooms,
		MaxMsgRate:                m.MaxMsgRate,
		AuthorizationDetailsTypes: m.AuthorizationDetailsTypes,
		CreatedAt:                 m.CreatedAt,
		Revoked:                   m.Revoked,
		ClientName:                m.ClientName,
		ClientURI:                 m.ClientURI,
		RedirectURIs:              m.RedirectURIs,
		GrantTypes:                m.GrantTypes,
		Scope:                     m.Scope,
		TokenEndpointAuthMethod:   m.TokenEndpointAuthMethod,
		RegistrationAccessToken:   m.RegistrationAccessToken,
		RegistrationClientURI:     m.RegistrationClientURI,
	}
}

// _ keeps core imported for build determinism if unused fields appear later.
var _ = core.AuthorizationDetail{}
