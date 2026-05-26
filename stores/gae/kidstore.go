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

func (s *GAEKidStore) Remove(ctx context.Context, req *keys.RemoveKidRequest) (*keys.RemoveKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Remove: req is required")
	}
	if err := s.client.Delete(ctx, s.namespacedKey(req.Kid)); err != nil {
		return nil, err
	}
	return &keys.RemoveKidResponse{}, nil
}

func (s *GAEKidStore) GetKey(ctx context.Context, req *keys.GetKeyRequest) (*keys.GetKeyResponse, error) {
	return nil, keys.ErrKeyNotFound
}

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
