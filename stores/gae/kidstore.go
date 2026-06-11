//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/keys"
)

const KindKidKey = "KidKey"

// KidKeyEntity is the Datastore entity for kid→key grace entries.
type KidKeyEntity struct {
	Key       *datastore.Key `datastore:"__key__"`
	KeyBytes  []byte         `datastore:"key_bytes,noindex"`
	Algorithm string         `datastore:"algorithm"`
	ClientID  string         `datastore:"client_id"`
	ExpiresAt time.Time      `datastore:"expires_at,noindex"`
}

// GAEKidStore implements keys.KidStorage using Google Cloud Datastore.
type GAEKidStore struct {
	client    *datastore.Client
	namespace string
}

var _ keys.KidStorage = (*GAEKidStore)(nil)

// NewKidStore creates a new Datastore-backed KidStorage.
func NewKidStore(client *datastore.Client, namespace string) *GAEKidStore {
	return &GAEKidStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *GAEKidStore) namespacedKey(name string) *datastore.Key {
	key := datastore.NameKey(KindKidKey, name, nil)
	key.Namespace = s.namespace
	return key
}

// Add registers a kid→key entry in the verification-only grace cache used
// during key rotation. The Key field must be []byte (HMAC secret or marshaled
// PEM); any other concrete type is rejected with keys.ErrAlgorithmMismatch.
// ExpiresAt of the zero time means "never expires"; otherwise GetKeyByKid
// treats now > ExpiresAt as not-found. Existing entries with the same kid
// are overwritten — KidStorage has no separate "create vs update" verb.
func (s *GAEKidStore) Add(ctx context.Context, req *keys.AddKidRequest) (*keys.AddKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Add: req is required")
	}
	keyBytes, ok := req.Key.([]byte)
	if !ok {
		return nil, keys.ErrAlgorithmMismatch
	}

	entity := &KidKeyEntity{
		Key:       s.namespacedKey(req.Kid),
		KeyBytes:  keyBytes,
		Algorithm: req.Algorithm,
		ClientID:  req.ClientID,
		ExpiresAt: req.ExpiresAt,
	}
	if _, err := s.client.Put(ctx, entity.Key, entity); err != nil {
		return nil, err
	}
	return &keys.AddKidResponse{}, nil
}

// Remove is idempotent — Datastore's Delete silently succeeds on missing
// keys, and KidStorage's contract permits that ("removing a kid that was
// never added is not an error"). The verification-only nature of the grace
// cache means a stale Remove during rotation is harmless.
func (s *GAEKidStore) Remove(ctx context.Context, req *keys.RemoveKidRequest) (*keys.RemoveKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Remove: req is required")
	}
	if err := s.client.Delete(ctx, s.namespacedKey(req.Kid)); err != nil {
		return nil, err
	}
	return &keys.RemoveKidResponse{}, nil
}

// GetKey always returns keys.ErrKeyNotFound. KidStorage is a verification-only
// grace cache keyed by kid, not by client_id — there is no way to ask "give
// me the rotation key for this client" because rotation entries are scoped
// to a kid, not a subject. Callers should reach for GetKeyByKid instead.
// The method exists only because keys.KidStorage embeds keys.KeyLookup
// (which carries this verb); the not-found sentinel is the documented
// behavior across all KidStorage backends, not a GAE-specific gap.
func (s *GAEKidStore) GetKey(ctx context.Context, req *keys.GetKeyRequest) (*keys.GetKeyResponse, error) {
	return nil, keys.ErrKeyNotFound
}

// GetKeyByKid resolves a kid to its grace-period key during rotation.
// Returns keys.ErrKidNotFound when no entry exists or when ExpiresAt is
// non-zero and already in the past. The expiry check runs on read so a
// cleanup job that hasn't yet swept stale entries doesn't return them as
// valid — CleanExpired's role is reclaiming storage, not gating reads.
func (s *GAEKidStore) GetKeyByKid(ctx context.Context, req *keys.GetKeyByKidRequest) (*keys.GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
	var entity KidKeyEntity
	if err := s.client.Get(ctx, s.namespacedKey(req.Kid), &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, keys.ErrKidNotFound
		}
		return nil, err
	}
	if !entity.ExpiresAt.IsZero() && time.Now().After(entity.ExpiresAt) {
		return nil, keys.ErrKidNotFound
	}
	return &keys.GetKeyByKidResponse{Record: &keys.KeyRecord{
		ClientID:  entity.ClientID,
		Key:       entity.KeyBytes,
		Algorithm: entity.Algorithm,
		Kid:       req.Kid,
	}}, nil
}

// CleanExpired sweeps the grace cache for entries whose ExpiresAt has passed
// and returns the number removed. Implementation reads every entity in the
// namespace and filters in process — Datastore doesn't expose a "delete
// where" verb, and the grace cache is small (bounded by rotation cardinality
// × grace period). Entries with zero ExpiresAt are immortal and skipped.
// Safe to call concurrently with GetKeyByKid; reads filter on their own
// independently.
func (s *GAEKidStore) CleanExpired(ctx context.Context, req *keys.CleanExpiredRequest) (*keys.CleanExpiredResponse, error) {
	q := datastore.NewQuery(KindKidKey)
	if s.namespace != "" {
		q = q.Namespace(s.namespace)
	}
	var entities []KidKeyEntity
	dsKeys, err := s.client.GetAll(ctx, q, &entities)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var toDelete []*datastore.Key
	for i, e := range entities {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			toDelete = append(toDelete, dsKeys[i])
		}
	}
	if len(toDelete) == 0 {
		return &keys.CleanExpiredResponse{}, nil
	}
	if err := s.client.DeleteMulti(ctx, toDelete); err != nil {
		return nil, err
	}
	return &keys.CleanExpiredResponse{Removed: len(toDelete)}, nil
}
