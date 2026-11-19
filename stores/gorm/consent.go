//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"errors"
	"slices"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/panyam/oneauth/core"
)

// ConsentModel is the GORM row for a core.ConsentGrant. Subject and
// ClientID form the composite primary key, so the table holds at most one
// grant per user and client. Scopes is a JSON array, like the scope lists
// on the token tables. A NULL ExpiresAt is a grant that never expires.
type ConsentModel struct {
	Subject   string      `gorm:"primaryKey;size:255"`
	ClientID  string      `gorm:"primaryKey;size:255"`
	Scopes    StringSlice `gorm:"type:jsonb"`
	GrantedAt time.Time   `gorm:"not null"`
	ExpiresAt *time.Time
}

// TableName pins the table name so a future GORM version cannot rename it.
func (ConsentModel) TableName() string {
	return "consents"
}

func consentToModel(g *core.ConsentGrant) *ConsentModel {
	m := &ConsentModel{
		Subject:   g.Subject,
		ClientID:  g.ClientID,
		Scopes:    StringSlice(slices.Clone(g.Scopes)),
		GrantedAt: g.GrantedAt,
	}
	if !g.ExpiresAt.IsZero() {
		t := g.ExpiresAt
		m.ExpiresAt = &t
	}
	return m
}

func modelToConsent(m *ConsentModel) *core.ConsentGrant {
	g := &core.ConsentGrant{
		Subject:   m.Subject,
		ClientID:  m.ClientID,
		Scopes:    []string(m.Scopes),
		GrantedAt: m.GrantedAt,
	}
	if m.ExpiresAt != nil {
		g.ExpiresAt = *m.ExpiresAt
	}
	return g
}

// ConsentStore implements core.ConsentStore on GORM. Every node reads the
// same table, so an approval given through one node lets a later
// prompt=none request on any node skip the consent screen.
type ConsentStore struct {
	db *gorm.DB
}

// NewConsentStore wraps an existing *gorm.DB. The caller runs AutoMigrate
// (this package's covers the consents table) before first use.
func NewConsentStore(db *gorm.DB) *ConsentStore {
	return &ConsentStore{db: db}
}

// SaveConsent upserts req.Grant in one statement (INSERT ... ON CONFLICT
// DO UPDATE), replacing every column of any grant for the same subject and
// client_id. Two racing saves leave one of the two grants, never a mix.
// Empty subject or client_id is an error.
func (s *ConsentStore) SaveConsent(ctx context.Context, req *core.SaveConsentRequest) (*core.SaveConsentResponse, error) {
	if req == nil || req.Grant == nil {
		return nil, errors.New("SaveConsent: grant is required")
	}
	if req.Grant.Subject == "" || req.Grant.ClientID == "" {
		return nil, errors.New("SaveConsent: subject and client_id are required")
	}
	m := consentToModel(req.Grant)
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(m).Error; err != nil {
		return nil, err
	}
	return &core.SaveConsentResponse{Grant: modelToConsent(consentToModel(req.Grant))}, nil
}

// GetConsent returns the stored grant, expired or not, or
// core.ErrConsentNotFound (gorm.ErrRecordNotFound maps to it). Other
// database errors pass through.
func (s *ConsentStore) GetConsent(ctx context.Context, req *core.GetConsentRequest) (*core.GetConsentResponse, error) {
	if req == nil || req.Subject == "" || req.ClientID == "" {
		return nil, core.ErrConsentNotFound
	}
	var m ConsentModel
	if err := s.db.WithContext(ctx).First(&m, "subject = ? AND client_id = ?", req.Subject, req.ClientID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrConsentNotFound
		}
		return nil, err
	}
	return &core.GetConsentResponse{Grant: modelToConsent(&m)}, nil
}

// RevokeConsent deletes the row. Deleting a missing row is not an error,
// so a second revoke succeeds.
func (s *ConsentStore) RevokeConsent(ctx context.Context, req *core.RevokeConsentRequest) (*core.RevokeConsentResponse, error) {
	if req == nil || req.Subject == "" || req.ClientID == "" {
		return &core.RevokeConsentResponse{}, nil
	}
	err := s.db.WithContext(ctx).Where("subject = ? AND client_id = ?", req.Subject, req.ClientID).
		Delete(&ConsentModel{}).Error
	if err != nil {
		return nil, err
	}
	return &core.RevokeConsentResponse{}, nil
}

var _ core.ConsentStore = (*ConsentStore)(nil)
