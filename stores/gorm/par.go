//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"errors"
	"net/url"
	"time"

	"gorm.io/gorm"

	"github.com/panyam/oneauth/core"
)

// PushedAuthorizationRequestModel is the GORM row for an RFC 9126 pushed
// authorization request.
//
// Payload is the pushed parameter set serialized as JSON rather than spread
// across typed columns. RFC 9126 §2.1 accepts any authorization-endpoint
// parameter including extensions, so a column per parameter would silently
// drop whatever this version of the server does not know about, which is
// the RFC 9396 case PAR exists to carry.
//
// ClientID is indexed because operators reach for "what did this client
// push" when debugging a flow, and ExpiresAt because the cleanup sweep
// scans on it.
type PushedAuthorizationRequestModel struct {
	RequestURI string     `gorm:"primaryKey;size:512"`
	ClientID   string     `gorm:"size:128;not null;index"`
	Payload    url.Values `gorm:"serializer:json"`
	Consumed   bool       `gorm:"not null;default:false"`
	CreatedAt  time.Time  `gorm:"autoCreateTime"`
	ExpiresAt  time.Time  `gorm:"not null;index"`
}

// TableName pins the table name so a future GORM version cannot rename it.
func (PushedAuthorizationRequestModel) TableName() string {
	return "pushed_authorization_requests"
}

func pushedToModel(r *core.PushedAuthorizationRequest) *PushedAuthorizationRequestModel {
	return &PushedAuthorizationRequestModel{
		RequestURI: r.RequestURI,
		ClientID:   r.ClientID,
		Payload:    r.Payload,
		Consumed:   r.Consumed,
		CreatedAt:  r.CreatedAt,
		ExpiresAt:  r.ExpiresAt,
	}
}

func modelToPushed(m *PushedAuthorizationRequestModel) *core.PushedAuthorizationRequest {
	return &core.PushedAuthorizationRequest{
		RequestURI: m.RequestURI,
		ClientID:   m.ClientID,
		Payload:    m.Payload,
		Consumed:   m.Consumed,
		CreatedAt:  m.CreatedAt,
		ExpiresAt:  m.ExpiresAt,
	}
}

// PushedAuthorizationRequestStore implements
// core.PushedAuthorizationRequestStore on GORM. This is the backend a
// multi-node deployment needs: a request_uri minted by whichever node
// served /par has to resolve on whichever node serves /authorize, and an
// in-process store cannot do that.
type PushedAuthorizationRequestStore struct {
	db *gorm.DB
}

// NewPushedAuthorizationRequestStore wraps an existing *gorm.DB. The caller
// runs AutoMigrate (this package's covers the table) before first use.
func NewPushedAuthorizationRequestStore(db *gorm.DB) *PushedAuthorizationRequestStore {
	return &PushedAuthorizationRequestStore{db: db}
}

// CreatePushedAuthorizationRequest inserts a record. A duplicate
// request_uri returns a generic error, matching the in-memory store: the
// caller drew the value from a CSPRNG, so a collision is a bug rather than
// a condition worth a typed sentinel.
func (s *PushedAuthorizationRequestStore) CreatePushedAuthorizationRequest(ctx context.Context, req *core.CreatePushedAuthorizationRequestRequest) (*core.CreatePushedAuthorizationRequestResponse, error) {
	if req == nil || req.Request == nil {
		return nil, errors.New("CreatePushedAuthorizationRequest: request is required")
	}
	r := req.Request
	if r.RequestURI == "" {
		return nil, errors.New("CreatePushedAuthorizationRequest: request_uri is required")
	}

	// Pre-check so the message matches the in-memory store whichever
	// driver's constraint error would otherwise surface. Cheap: primary-key
	// lookup.
	var existing int64
	if err := s.db.WithContext(ctx).Model(&PushedAuthorizationRequestModel{}).
		Where("request_uri = ?", r.RequestURI).Count(&existing).Error; err != nil {
		return nil, err
	}
	if existing > 0 {
		return nil, errors.New("CreatePushedAuthorizationRequest: request_uri collision")
	}

	if err := s.db.WithContext(ctx).Create(pushedToModel(r)).Error; err != nil {
		return nil, err
	}
	return &core.CreatePushedAuthorizationRequestResponse{Request: r}, nil
}

// GetPushedAuthorizationRequest returns the record or
// core.ErrPushedRequestNotFound. It does not filter by expiry or
// consumption, so the authorization endpoint can tell a client that its
// reference expired rather than that it never existed.
func (s *PushedAuthorizationRequestStore) GetPushedAuthorizationRequest(ctx context.Context, req *core.GetPushedAuthorizationRequestRequest) (*core.GetPushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	var model PushedAuthorizationRequestModel
	if err := s.db.WithContext(ctx).First(&model, "request_uri = ?", req.RequestURI).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, core.ErrPushedRequestNotFound
		}
		return nil, err
	}
	return &core.GetPushedAuthorizationRequestResponse{Request: modelToPushed(&model)}, nil
}

// ConsumePushedAuthorizationRequest marks the record redeemed, leaving the
// row in place so a replay reads back as "already used" rather than as an
// unknown reference. Returns core.ErrPushedRequestNotFound when nothing
// matches.
func (s *PushedAuthorizationRequestStore) ConsumePushedAuthorizationRequest(ctx context.Context, req *core.ConsumePushedAuthorizationRequestRequest) (*core.ConsumePushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	result := s.db.WithContext(ctx).Model(&PushedAuthorizationRequestModel{}).
		Where("request_uri = ?", req.RequestURI).
		Update("consumed", true)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, core.ErrPushedRequestNotFound
	}
	return &core.ConsumePushedAuthorizationRequestResponse{}, nil
}

// DeletePushedAuthorizationRequest removes a record, returning
// core.ErrPushedRequestNotFound when nothing matched so a caller can tell a
// second delete from a first.
func (s *PushedAuthorizationRequestStore) DeletePushedAuthorizationRequest(ctx context.Context, req *core.DeletePushedAuthorizationRequestRequest) (*core.DeletePushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	result := s.db.WithContext(ctx).Where("request_uri = ?", req.RequestURI).
		Delete(&PushedAuthorizationRequestModel{})
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, core.ErrPushedRequestNotFound
	}
	return &core.DeletePushedAuthorizationRequestResponse{}, nil
}

// CleanupExpiredPushedRequests drops every expired record, consumed or not.
// Consumed rows are the bulk of what accumulates, so a sweep that spared
// them would grow the table without bound.
func (s *PushedAuthorizationRequestStore) CleanupExpiredPushedRequests(ctx context.Context, _ *core.CleanupExpiredPushedRequestsRequest) (*core.CleanupExpiredPushedRequestsResponse, error) {
	result := s.db.WithContext(ctx).Where("expires_at <= ?", time.Now()).
		Delete(&PushedAuthorizationRequestModel{})
	if result.Error != nil {
		return nil, result.Error
	}
	return &core.CleanupExpiredPushedRequestsResponse{Removed: int(result.RowsAffected)}, nil
}

var _ core.PushedAuthorizationRequestStore = (*PushedAuthorizationRequestStore)(nil)
