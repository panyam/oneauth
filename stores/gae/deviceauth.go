//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/core"
	"google.golang.org/api/iterator"
)

// KindDeviceAuthorization is the Datastore Kind for RFC 8628 device
// authorization records. Exported so tests can drive bulk cleanup
// without poking the entity name string from inside the test setup.
const KindDeviceAuthorization = "DeviceAuthorization"

// DeviceAuthorizationEntity is the Datastore entity for a single device
// authorization. Two properties carry indexes:
//
//   - UserCodeUpper — the case/dash-normalized form used by
//     GetByUserCode. Indexed because it's the only secondary lookup
//     path. The original UserCode column preserves the display form
//     (XXXX-XXXX) the device showed the user.
//   - ExpiresAt — indexed so CleanupExpired's range query stays
//     selective as the table grows.
//
// Every other property is noindex. Datastore's 1500-byte per-property
// index limit is irrelevant for the unindexed string fields, and
// disabling indexing saves write cost.
//
// Times are stored as unix nanos (int64) — Datastore truncates
// time.Time to microsecond precision, and the unix-nanos round-trip
// matches what GAEAppStore already does for the same reason.
type DeviceAuthorizationEntity struct {
	Key               *datastore.Key `datastore:"__key__"`
	DeviceCode        string         `datastore:"device_code,noindex"`
	UserCode          string         `datastore:"user_code,noindex"`
	UserCodeUpper     string         `datastore:"user_code_upper"`
	ClientID          string         `datastore:"client_id,noindex"`
	Scopes            []string       `datastore:"scopes,noindex"`
	RequestedAudience string         `datastore:"requested_audience,noindex"`
	Status            string         `datastore:"status,noindex"`
	ApprovedSubject   string         `datastore:"approved_subject,noindex"`
	CreatedAt         int64          `datastore:"created_at,noindex"`
	ExpiresAt         int64          `datastore:"expires_at"`
	LastPolledAt      int64          `datastore:"last_polled_at,noindex"`
	IntervalSeconds   int            `datastore:"interval_seconds,noindex"`
}

// GAEDeviceAuthStore implements core.DeviceAuthorizationStore on Google
// Cloud Datastore. Multi-node compatible (Datastore is the shared source
// of truth) and slots into stores/gae/ alongside GAEAppStore, GAEKeyStore,
// and GAEKidStore (issue 270).
type GAEDeviceAuthStore struct {
	client    *datastore.Client
	namespace string
}

var _ core.DeviceAuthorizationStore = (*GAEDeviceAuthStore)(nil)

// NewDeviceAuthStore creates a new Datastore-backed
// DeviceAuthorizationStore. The namespace lets multiple oneauth
// deployments share a single Datastore project without collisions.
func NewDeviceAuthStore(client *datastore.Client, namespace string) *GAEDeviceAuthStore {
	return &GAEDeviceAuthStore{
		client:    client,
		namespace: namespace,
	}
}

// deviceKey is the canonical key derivation for an entity. The
// device_code is the entity name; the Kind + Namespace come from the
// store. Used by every lookup-by-device_code path.
func (s *GAEDeviceAuthStore) deviceKey(deviceCode string) *datastore.Key {
	key := datastore.NameKey(KindDeviceAuthorization, deviceCode, nil)
	key.Namespace = s.namespace
	return key
}

// CreateDeviceAuthorization inserts a new authorization. Empty
// device_code or user_code is rejected; collisions on either return a
// generic error matching the in-memory store's wording so a downstream
// shared contract suite stays uniform.
//
// The collision check is a two-step probe (Get by device_code key, then
// query by user_code_upper). Without a transaction this is racy under
// concurrent writes — the entity-key Put at the end provides serializing
// last-write-wins semantics, but two simultaneous create-with-same-code
// requests could both pass the pre-check and both write. That race is
// acceptable for the device-code path (256 bits of entropy makes
// collision a programmer error, not a real failure mode) and for the
// user_code path (the caller draws from the same CSPRNG).
func (s *GAEDeviceAuthStore) CreateDeviceAuthorization(ctx context.Context, req *core.CreateDeviceAuthorizationRequest) (*core.CreateDeviceAuthorizationResponse, error) {
	if req == nil || req.Authorization == nil {
		return nil, errors.New("CreateDeviceAuthorization: authorization is required")
	}
	a := req.Authorization
	if a.DeviceCode == "" || a.UserCode == "" {
		return nil, errors.New("CreateDeviceAuthorization: device_code and user_code are required")
	}
	upper := core.UpperUserCode(a.UserCode)

	var probe DeviceAuthorizationEntity
	if err := s.client.Get(ctx, s.deviceKey(a.DeviceCode), &probe); err == nil {
		return nil, errors.New("CreateDeviceAuthorization: device_code collision")
	} else if !errors.Is(err, datastore.ErrNoSuchEntity) {
		return nil, fmt.Errorf("CreateDeviceAuthorization: probe device_code: %w", err)
	}

	q := datastore.NewQuery(KindDeviceAuthorization).
		Namespace(s.namespace).
		FilterField("user_code_upper", "=", upper).
		KeysOnly().
		Limit(1)
	keys, err := s.client.GetAll(ctx, q, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateDeviceAuthorization: probe user_code: %w", err)
	}
	if len(keys) > 0 {
		return nil, errors.New("CreateDeviceAuthorization: user_code collision")
	}

	entity := deviceAuthToEntity(s.deviceKey(a.DeviceCode), a)
	entity.UserCodeUpper = upper
	if _, err := s.client.Put(ctx, entity.Key, entity); err != nil {
		return nil, err
	}
	return &core.CreateDeviceAuthorizationResponse{}, nil
}

// GetByDeviceCode returns the authorization for the given device_code,
// or ErrDeviceAuthorizationNotFound. Does NOT filter by status or
// expiry — the caller (the token endpoint handler) checks both.
func (s *GAEDeviceAuthStore) GetByDeviceCode(ctx context.Context, req *core.GetByDeviceCodeRequest) (*core.GetByDeviceCodeResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	var entity DeviceAuthorizationEntity
	if err := s.client.Get(ctx, s.deviceKey(req.DeviceCode), &entity); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, err
	}
	return &core.GetByDeviceCodeResponse{Authorization: entityToDeviceAuth(&entity)}, nil
}

// GetByUserCode returns the authorization for the given user_code
// (case- and dash-insensitive comparison), or
// ErrDeviceAuthorizationNotFound. Query by the indexed user_code_upper
// property — O(log n) at the Datastore tier.
func (s *GAEDeviceAuthStore) GetByUserCode(ctx context.Context, req *core.GetByUserCodeRequest) (*core.GetByUserCodeResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	q := datastore.NewQuery(KindDeviceAuthorization).
		Namespace(s.namespace).
		FilterField("user_code_upper", "=", core.UpperUserCode(req.UserCode)).
		Limit(1)
	it := s.client.Run(ctx, q)
	var entity DeviceAuthorizationEntity
	if _, err := it.Next(&entity); err != nil {
		if errors.Is(err, iterator.Done) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, fmt.Errorf("GetByUserCode iterate: %w", err)
	}
	return &core.GetByUserCodeResponse{Authorization: entityToDeviceAuth(&entity)}, nil
}

// ApproveDeviceAuthorization transitions a pending authorization to
// approved and binds the subject + scopes. Wrapped in a Datastore
// transaction so two concurrent approvers don't both win — the second
// transaction commits against stale state and returns
// ErrDeviceAuthorizationNotFound (matching InMemoryDeviceAuthorizationStore
// semantics: the second writer sees the no-pending-record state).
func (s *GAEDeviceAuthStore) ApproveDeviceAuthorization(ctx context.Context, req *core.ApproveDeviceAuthorizationRequest) (*core.ApproveDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	upper := core.UpperUserCode(req.UserCode)

	var out core.DeviceAuthorization
	_, txErr := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		key, found, err := s.findPendingByUserCodeTx(ctx, tx, upper)
		if err != nil {
			return err
		}
		if !found {
			return core.ErrDeviceAuthorizationNotFound
		}
		var entity DeviceAuthorizationEntity
		if err := tx.Get(key, &entity); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return core.ErrDeviceAuthorizationNotFound
			}
			return err
		}
		if entity.Status != string(core.DeviceAuthorizationStatusPending) {
			return core.ErrDeviceAuthorizationNotFound
		}
		entity.Status = string(core.DeviceAuthorizationStatusApproved)
		entity.ApprovedSubject = req.ApprovedSubject
		if req.GrantedScopes != nil {
			entity.Scopes = req.GrantedScopes
		}
		if _, err := tx.Put(key, &entity); err != nil {
			return err
		}
		out = *entityToDeviceAuth(&entity)
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &core.ApproveDeviceAuthorizationResponse{Authorization: &out}, nil
}

// DenyDeviceAuthorization transitions a pending authorization to
// denied. Wrapped in a transaction for the same reason as
// ApproveDeviceAuthorization.
func (s *GAEDeviceAuthStore) DenyDeviceAuthorization(ctx context.Context, req *core.DenyDeviceAuthorizationRequest) (*core.DenyDeviceAuthorizationResponse, error) {
	if req == nil || req.UserCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	upper := core.UpperUserCode(req.UserCode)

	_, txErr := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		key, found, err := s.findPendingByUserCodeTx(ctx, tx, upper)
		if err != nil {
			return err
		}
		if !found {
			return core.ErrDeviceAuthorizationNotFound
		}
		var entity DeviceAuthorizationEntity
		if err := tx.Get(key, &entity); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return core.ErrDeviceAuthorizationNotFound
			}
			return err
		}
		if entity.Status != string(core.DeviceAuthorizationStatusPending) {
			return core.ErrDeviceAuthorizationNotFound
		}
		entity.Status = string(core.DeviceAuthorizationStatusDenied)
		if _, err := tx.Put(key, &entity); err != nil {
			return err
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &core.DenyDeviceAuthorizationResponse{}, nil
}

// UpdatePollingState records a poll attempt — always updates
// LastPolledAt; raises IntervalSeconds by 5 when SlowDown is true
// (RFC 8628 §3.5). Read-modify-write inside a transaction so concurrent
// polls don't lose interval bumps.
func (s *GAEDeviceAuthStore) UpdatePollingState(ctx context.Context, req *core.UpdatePollingStateRequest) (*core.UpdatePollingStateResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	key := s.deviceKey(req.DeviceCode)

	var out core.DeviceAuthorization
	_, txErr := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var entity DeviceAuthorizationEntity
		if err := tx.Get(key, &entity); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return core.ErrDeviceAuthorizationNotFound
			}
			return err
		}
		entity.LastPolledAt = req.PolledAt.UnixNano()
		if req.SlowDown {
			entity.IntervalSeconds += 5
		}
		if _, err := tx.Put(key, &entity); err != nil {
			return err
		}
		out = *entityToDeviceAuth(&entity)
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &core.UpdatePollingStateResponse{Authorization: &out}, nil
}

// DeleteDeviceAuthorization removes the authorization. Returns
// ErrDeviceAuthorizationNotFound when no record matches. Datastore's
// bare Delete is idempotent (silent success on missing keys), so we
// Get-then-Delete to honor the contract — same pattern GAEAppStore uses
// for ErrAppNotFound parity.
func (s *GAEDeviceAuthStore) DeleteDeviceAuthorization(ctx context.Context, req *core.DeleteDeviceAuthorizationRequest) (*core.DeleteDeviceAuthorizationResponse, error) {
	if req == nil || req.DeviceCode == "" {
		return nil, core.ErrDeviceAuthorizationNotFound
	}
	key := s.deviceKey(req.DeviceCode)
	var probe DeviceAuthorizationEntity
	if err := s.client.Get(ctx, key, &probe); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return nil, core.ErrDeviceAuthorizationNotFound
		}
		return nil, err
	}
	if err := s.client.Delete(ctx, key); err != nil {
		return nil, err
	}
	return &core.DeleteDeviceAuthorizationResponse{}, nil
}

// CleanupExpired enumerates the store and removes every record whose
// ExpiresAt is at or before the current wall-clock time. Uses the
// indexed expires_at property + DeleteMulti so the call cost scales
// with the number of expired records, not the table size.
func (s *GAEDeviceAuthStore) CleanupExpired(ctx context.Context, _ *core.CleanupExpiredDeviceAuthsRequest) (*core.CleanupExpiredDeviceAuthsResponse, error) {
	now := time.Now().UnixNano()
	q := datastore.NewQuery(KindDeviceAuthorization).
		Namespace(s.namespace).
		FilterField("expires_at", "<=", now).
		KeysOnly()
	keys, err := s.client.GetAll(ctx, q, nil)
	if err != nil {
		return nil, fmt.Errorf("CleanupExpired query: %w", err)
	}
	if len(keys) == 0 {
		return &core.CleanupExpiredDeviceAuthsResponse{Removed: 0}, nil
	}
	if err := s.client.DeleteMulti(ctx, keys); err != nil {
		return nil, fmt.Errorf("CleanupExpired delete: %w", err)
	}
	return &core.CleanupExpiredDeviceAuthsResponse{Removed: len(keys)}, nil
}

// findPendingByUserCodeTx looks up the entity key for a pending
// authorization with the given normalized user_code. Returns
// (key, true, nil) on hit, (nil, false, nil) when nothing matches.
// Used by the Approve / Deny transaction bodies.
func (s *GAEDeviceAuthStore) findPendingByUserCodeTx(ctx context.Context, _ *datastore.Transaction, upper string) (*datastore.Key, bool, error) {
	q := datastore.NewQuery(KindDeviceAuthorization).
		Namespace(s.namespace).
		FilterField("user_code_upper", "=", upper).
		KeysOnly().
		Limit(1)
	keys, err := s.client.GetAll(ctx, q, nil)
	if err != nil {
		return nil, false, err
	}
	if len(keys) == 0 {
		return nil, false, nil
	}
	return keys[0], true, nil
}

// deviceAuthToEntity maps the public struct onto the Datastore entity.
// UserCodeUpper is populated by the caller (CreateDeviceAuthorization)
// so the normalization rule lives in one place.
func deviceAuthToEntity(key *datastore.Key, a *core.DeviceAuthorization) *DeviceAuthorizationEntity {
	entity := &DeviceAuthorizationEntity{
		Key:               key,
		DeviceCode:        a.DeviceCode,
		UserCode:          a.UserCode,
		ClientID:          a.ClientID,
		Scopes:            a.Scopes,
		RequestedAudience: a.RequestedAudience,
		Status:            string(a.Status),
		ApprovedSubject:   a.ApprovedSubject,
		CreatedAt:         a.CreatedAt.UnixNano(),
		ExpiresAt:         a.ExpiresAt.UnixNano(),
		IntervalSeconds:   a.IntervalSeconds,
	}
	if !a.LastPolledAt.IsZero() {
		entity.LastPolledAt = a.LastPolledAt.UnixNano()
	}
	return entity
}

// entityToDeviceAuth maps the Datastore entity back to the public
// struct. A zero LastPolledAt round-trips to the zero time.Time
// (matching InMemory / FS / GORM semantics).
func entityToDeviceAuth(e *DeviceAuthorizationEntity) *core.DeviceAuthorization {
	return &core.DeviceAuthorization{
		DeviceCode:        e.DeviceCode,
		UserCode:          e.UserCode,
		ClientID:          e.ClientID,
		Scopes:            e.Scopes,
		RequestedAudience: e.RequestedAudience,
		Status:            core.DeviceAuthorizationStatus(e.Status),
		ApprovedSubject:   e.ApprovedSubject,
		CreatedAt:         unixNanosToTime(e.CreatedAt),
		ExpiresAt:         unixNanosToTime(e.ExpiresAt),
		LastPolledAt:      unixNanosToTime(e.LastPolledAt),
		IntervalSeconds:   e.IntervalSeconds,
	}
}

