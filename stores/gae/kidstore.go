//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/keys"
)

const KindKidKey = "KidKey"

// KidKeyEntity is the Datastore entity for kid→key grace entries.
// The Datastore key name is the kid itself.
type KidKeyEntity struct {
	Key       *datastore.Key `datastore:"__key__"`
	KeyBytes  []byte         `datastore:"key_bytes,noindex"`
	Algorithm string         `datastore:"algorithm"`
	ClientID  string         `datastore:"client_id"`
	// ExpiresAt is unindexed: CleanExpired scans + filters in Go (kid
	// stores are small, and we'd need a not-equal-zero filter combined
	// with a less-than filter which Datastore doesn't support natively).
	ExpiresAt time.Time `datastore:"expires_at,noindex"`
}

// GAEKidStore implements keys.KidStorage using Google Cloud Datastore.
type GAEKidStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

var _ keys.KidStorage = (*GAEKidStore)(nil)

// NewKidStore creates a new Datastore-backed KidStorage.
func NewKidStore(client *datastore.Client, namespace string) *GAEKidStore {
	return &GAEKidStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

// WithContext returns a copy of the store with the given context, matching
// the GAEKeyStore.WithContext pattern (see issue 110 / 175 for the planned
// ctx-as-parameter migration).
func (s *GAEKidStore) WithContext(ctx context.Context) *GAEKidStore {
	return &GAEKidStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
	}
}

func (s *GAEKidStore) namespacedKey(name string) *datastore.Key {
	key := datastore.NameKey(KindKidKey, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *GAEKidStore) Add(kid string, key any, algorithm string, clientID string, expiresAt time.Time) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return keys.ErrAlgorithmMismatch
	}

	entity := &KidKeyEntity{
		Key:       s.namespacedKey(kid),
		KeyBytes:  keyBytes,
		Algorithm: algorithm,
		ClientID:  clientID,
		ExpiresAt: expiresAt,
	}
	_, err := s.client.Put(s.ctx, entity.Key, entity)
	return err
}

// Remove is idempotent — Datastore Delete on a missing key returns nil.
func (s *GAEKidStore) Remove(kid string) error {
	return s.client.Delete(s.ctx, s.namespacedKey(kid))
}

// GetKey always returns ErrKeyNotFound — KidStorage is kid-indexed.
func (s *GAEKidStore) GetKey(clientID string) (*keys.KeyRecord, error) {
	return nil, keys.ErrKeyNotFound
}

func (s *GAEKidStore) GetKeyByKid(kid string) (*keys.KeyRecord, error) {
	var entity KidKeyEntity
	if err := s.client.Get(s.ctx, s.namespacedKey(kid), &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, keys.ErrKidNotFound
		}
		return nil, err
	}
	if !entity.ExpiresAt.IsZero() && time.Now().After(entity.ExpiresAt) {
		return nil, keys.ErrKidNotFound
	}
	return &keys.KeyRecord{
		ClientID:  entity.ClientID,
		Key:       entity.KeyBytes,
		Algorithm: entity.Algorithm,
		Kid:       kid,
	}, nil
}

func (s *GAEKidStore) CleanExpired() error {
	q := datastore.NewQuery(KindKidKey)
	if s.namespace != "" {
		q = q.Namespace(s.namespace)
	}
	var entities []KidKeyEntity
	dsKeys, err := s.client.GetAll(s.ctx, q, &entities)
	if err != nil {
		return err
	}
	now := time.Now()
	var toDelete []*datastore.Key
	for i, e := range entities {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			toDelete = append(toDelete, dsKeys[i])
		}
	}
	if len(toDelete) == 0 {
		return nil
	}
	return s.client.DeleteMulti(s.ctx, toDelete)
}
