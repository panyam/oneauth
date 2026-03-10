//go:build !wasm
// +build !wasm

package gae

import (
	"context"

	"cloud.google.com/go/datastore"
	oa "github.com/panyam/oneauth"
)

const KindSigningKey = "SigningKey"

// SigningKeyEntity is the Datastore entity for per-client signing keys.
type SigningKeyEntity struct {
	Key       *datastore.Key `datastore:"__key__"`
	KeyBytes  []byte         `datastore:"key_bytes,noindex"`
	Algorithm string         `datastore:"algorithm"`
}

// GAEKeyStore implements oa.WritableKeyStore using Google Cloud Datastore.
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

func (s *GAEKeyStore) RegisterKey(clientID string, key any, algorithm string) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return oa.ErrAlgorithmMismatch
	}

	entity := &SigningKeyEntity{
		Key:       s.namespacedKey(clientID),
		KeyBytes:  keyBytes,
		Algorithm: algorithm,
	}
	_, err := s.client.Put(s.ctx, entity.Key, entity)
	return err
}

func (s *GAEKeyStore) DeleteKey(clientID string) error {
	key := s.namespacedKey(clientID)

	// Check existence first
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

func (s *GAEKeyStore) GetVerifyKey(clientID string) (any, error) {
	entity, err := s.getEntity(clientID)
	if err != nil {
		return nil, err
	}
	return entity.KeyBytes, nil
}

func (s *GAEKeyStore) GetSigningKey(clientID string) (any, error) {
	return s.GetVerifyKey(clientID)
}

func (s *GAEKeyStore) GetExpectedAlg(clientID string) (string, error) {
	entity, err := s.getEntity(clientID)
	if err != nil {
		return "", err
	}
	return entity.Algorithm, nil
}

func (s *GAEKeyStore) ListKeys() ([]string, error) {
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
