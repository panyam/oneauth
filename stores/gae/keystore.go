//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"fmt"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const KindSigningKey = "SigningKey"

// SigningKeyEntity is the Datastore entity for per-client signing keys.
type SigningKeyEntity struct {
	Key       *datastore.Key `datastore:"__key__"`
	KeyBytes  []byte         `datastore:"key_bytes,noindex"`
	Algorithm string         `datastore:"algorithm"`
	Kid       string         `datastore:"kid"`
}

// GAEKeyStore implements keys.KeyStorage using Google Cloud Datastore.
type GAEKeyStore struct {
	client    *datastore.Client
	namespace string
}

// NewKeyStore creates a new Datastore-backed KeyStore.
func NewKeyStore(client *datastore.Client, namespace string) *GAEKeyStore {
	return &GAEKeyStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *GAEKeyStore) namespacedKey(name string) *datastore.Key {
	key := datastore.NameKey(KindSigningKey, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *GAEKeyStore) PutKey(ctx context.Context, req *keys.PutKeyRequest) (*keys.PutKeyResponse, error) {
	if req == nil || req.Record == nil {
		return nil, fmt.Errorf("PutKey: req.Record is required")
	}
	rec := req.Record
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return nil, keys.ErrAlgorithmMismatch
	}

	kid := rec.Kid
	if kid == "" {
		kid, _ = utils.ComputeKid(keyBytes, rec.Algorithm)
	}

	entity := &SigningKeyEntity{
		Key:       s.namespacedKey(rec.ClientID),
		KeyBytes:  keyBytes,
		Algorithm: rec.Algorithm,
		Kid:       kid,
	}
	if _, err := s.client.Put(ctx, entity.Key, entity); err != nil {
		return nil, err
	}
	return &keys.PutKeyResponse{}, nil
}

func (s *GAEKeyStore) DeleteKey(ctx context.Context, req *keys.DeleteKeyRequest) (*keys.DeleteKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteKey: req is required")
	}
	key := s.namespacedKey(req.ClientID)
	var entity SigningKeyEntity
	if err := s.client.Get(ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, keys.ErrKeyNotFound
		}
		return nil, err
	}
	if err := s.client.Delete(ctx, key); err != nil {
		return nil, err
	}
	return &keys.DeleteKeyResponse{}, nil
}

func (s *GAEKeyStore) getEntity(ctx context.Context, clientID string) (*SigningKeyEntity, error) {
	key := s.namespacedKey(clientID)
	var entity SigningKeyEntity
	if err := s.client.Get(ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, keys.ErrKeyNotFound
		}
		return nil, err
	}
	return &entity, nil
}

func (s *GAEKeyStore) GetKey(ctx context.Context, req *keys.GetKeyRequest) (*keys.GetKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKey: req is required")
	}
	entity, err := s.getEntity(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	return &keys.GetKeyResponse{Record: &keys.KeyRecord{
		ClientID:  req.ClientID,
		Key:       entity.KeyBytes,
		Algorithm: entity.Algorithm,
		Kid:       entity.Kid,
	}}, nil
}

func (s *GAEKeyStore) GetKeyByKid(ctx context.Context, req *keys.GetKeyByKidRequest) (*keys.GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
	q := datastore.NewQuery(KindSigningKey).FilterField("kid", "=", req.Kid).Limit(1)
	if s.namespace != "" {
		q = q.Namespace(s.namespace)
	}
	var entities []SigningKeyEntity
	dsKeys, err := s.client.GetAll(ctx, q, &entities)
	if err != nil {
		return nil, err
	}
	if len(entities) == 0 {
		return nil, keys.ErrKidNotFound
	}
	return &keys.GetKeyByKidResponse{Record: &keys.KeyRecord{
		ClientID:  dsKeys[0].Name,
		Key:       entities[0].KeyBytes,
		Algorithm: entities[0].Algorithm,
		Kid:       entities[0].Kid,
	}}, nil
}

func (s *GAEKeyStore) ListKeyIDs(ctx context.Context, req *keys.ListKeyIDsRequest) (*keys.ListKeyIDsResponse, error) {
	q := datastore.NewQuery(KindSigningKey).KeysOnly()
	if s.namespace != "" {
		q = q.Namespace(s.namespace)
	}
	dsKeys, err := s.client.GetAll(ctx, q, nil)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(dsKeys))
	for i, k := range dsKeys {
		ids[i] = k.Name
	}
	return &keys.ListKeyIDsResponse{ClientIDs: ids}, nil
}
