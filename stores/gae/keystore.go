//go:build !wasm
// +build !wasm

package gae

import (
	"context"

	"cloud.google.com/go/datastore"
	oa "github.com/panyam/oneauth"
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

// GAEKeyStore implements oa.KeyStorage using Google Cloud Datastore.
type GAEKeyStore struct {
	client    *datastore.Client
	namespace string
	ctx       context.Context
}

// NewKeyStore creates a new Datastore-backed KeyStore.
func NewKeyStore(client *datastore.Client, namespace string) *GAEKeyStore {
	return &GAEKeyStore{
		client:    client,
		namespace: namespace,
		ctx:       context.Background(),
	}
}

// WithContext returns a copy of the store with the given context.
func (s *GAEKeyStore) WithContext(ctx context.Context) *GAEKeyStore {
	return &GAEKeyStore{
		client:    s.client,
		namespace: s.namespace,
		ctx:       ctx,
	}
}

func (s *GAEKeyStore) namespacedKey(name string) *datastore.Key {
	key := datastore.NameKey(KindSigningKey, name, nil)
	key.Namespace = s.namespace
	return key
}

func (s *GAEKeyStore) PutKey(rec *oa.KeyRecord) error {
	keyBytes, ok := rec.Key.([]byte)
	if !ok {
		return oa.ErrAlgorithmMismatch
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
	_, err := s.client.Put(s.ctx, entity.Key, entity)
	return err
}

func (s *GAEKeyStore) DeleteKey(clientID string) error {
	key := s.namespacedKey(clientID)
	var entity SigningKeyEntity
	if err := s.client.Get(s.ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return oa.ErrKeyNotFound
		}
		return err
	}
	return s.client.Delete(s.ctx, key)
}

func (s *GAEKeyStore) getEntity(clientID string) (*SigningKeyEntity, error) {
	key := s.namespacedKey(clientID)
	var entity SigningKeyEntity
	if err := s.client.Get(s.ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, oa.ErrKeyNotFound
		}
		return nil, err
	}
	return &entity, nil
}

func (s *GAEKeyStore) GetKey(clientID string) (*oa.KeyRecord, error) {
	entity, err := s.getEntity(clientID)
	if err != nil {
		return nil, err
	}
	return &oa.KeyRecord{
		ClientID:  clientID,
		Key:       entity.KeyBytes,
		Algorithm: entity.Algorithm,
		Kid:       entity.Kid,
	}, nil
}

func (s *GAEKeyStore) GetKeyByKid(kid string) (*oa.KeyRecord, error) {
	q := datastore.NewQuery(KindSigningKey).FilterField("kid", "=", kid).Limit(1)
	if s.namespace != "" {
		q = q.Namespace(s.namespace)
	}
	var entities []SigningKeyEntity
	keys, err := s.client.GetAll(s.ctx, q, &entities)
	if err != nil {
		return nil, err
	}
	if len(entities) == 0 {
		return nil, oa.ErrKidNotFound
	}
	return &oa.KeyRecord{
		ClientID:  keys[0].Name,
		Key:       entities[0].KeyBytes,
		Algorithm: entities[0].Algorithm,
		Kid:       entities[0].Kid,
	}, nil
}

func (s *GAEKeyStore) ListKeyIDs() ([]string, error) {
	q := datastore.NewQuery(KindSigningKey).KeysOnly()
	if s.namespace != "" {
		q = q.Namespace(s.namespace)
	}
	keys, err := s.client.GetAll(s.ctx, q, nil)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(keys))
	for i, k := range keys {
		result[i] = k.Name
	}
	return result, nil
}

// Backward-compatible aliases

func (s *GAEKeyStore) RegisterKey(clientID string, key any, algorithm string) error {
	return s.PutKey(&oa.KeyRecord{ClientID: clientID, Key: key, Algorithm: algorithm})
}

func (s *GAEKeyStore) GetVerifyKey(clientID string) (any, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return nil, err
	}
	return rec.Key, nil
}

func (s *GAEKeyStore) GetSigningKey(clientID string) (any, error) {
	return s.GetVerifyKey(clientID)
}

func (s *GAEKeyStore) GetExpectedAlg(clientID string) (string, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Algorithm, nil
}

func (s *GAEKeyStore) ListKeys() ([]string, error) {
	return s.ListKeyIDs()
}

func (s *GAEKeyStore) GetCurrentKid(clientID string) (string, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Kid, nil
}
