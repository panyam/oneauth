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

// PutKey upserts a per-client signing key. The record's Key field must be
// []byte (HMAC secret or marshaled PEM); any other concrete type is rejected
// with keys.ErrAlgorithmMismatch — KeyStorage callers serialize before
// reaching the backend, and a wrong type here means the caller skipped that
// step. Kid is filled in from utils.ComputeKid(KeyBytes, Algorithm) when the
// caller leaves it empty so JWKS lookups stay deterministic across restarts.
// Existing entries with the same ClientID are overwritten — KeyStorage has
// no separate "create vs update" verb.
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

// DeleteKey removes the signing-key entry for req.ClientID. Returns
// keys.ErrKeyNotFound when the entry is absent — Datastore's bare Delete is
// idempotent and silently succeeds on missing keys, so the implementation
// does a Get-then-Delete to honor the KeyStorage contract (the conformance
// suite asserts on this sentinel). Other Datastore errors (network, auth,
// quota) surface unwrapped so callers can distinguish "no such key" from
// "infrastructure problem."
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

// GetKey returns the signing-key record for req.ClientID, or
// keys.ErrKeyNotFound when the entry is absent. KeyBytes are returned as
// []byte (the same shape PutKey accepted) — callers are responsible for
// parsing back to the algorithm-specific key type.
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

// GetKeyByKid resolves a key by its kid (the JWT header identifier), used by
// JWKS-driven validators that only know the kid, not the client_id. Returns
// keys.ErrKidNotFound when no entry carries the requested kid. The query
// runs against the "kid" property — the only indexed non-key field on
// SigningKeyEntity — and reads at most one entity (Limit(1)) since kids are
// unique per JWKS surface.
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

// ListKeyIDs enumerates every client_id with a registered signing key in this
// namespace. Returns an empty slice (not an error) for an empty namespace,
// matching the other KeyStorage backends' "fresh store has no keys" shape.
// Order is unspecified — Datastore key-only queries return results in
// implementation-defined order; callers that need deterministic order must
// sort.
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
