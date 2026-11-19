//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/outbound"
)

// KindUserToken is the Datastore kind for outbound user tokens.
const KindUserToken = "OutboundUserToken"

// UserTokenEntity is the Datastore entity for outbound.UserTokenRecord.
// Sealed is ciphertext from outbound.UserTokens, unindexed since
// Datastore caps indexed values at 1500 bytes and nothing queries it.
type UserTokenEntity struct {
	Provider  string    `datastore:"provider"`
	Subject   string    `datastore:"subject"`
	Sealed    []byte    `datastore:"sealed,noindex"`
	Version   int64     `datastore:"version"`
	UpdatedAt time.Time `datastore:"updated_at"`
}

// GAEUserTokenStore implements outbound.UserTokenStore on Cloud
// Datastore. PutUserToken reads and writes inside one transaction, so
// compare-and-swap holds across replicas.
//
// Entities are keyed by a SHA-256 of provider and subject rather than
// the raw strings, so two keys can never share an entity. The entity
// also stores both fields, and a mismatch on read is an error.
type GAEUserTokenStore struct {
	client    *datastore.Client
	namespace string
}

// NewUserTokenStore returns a store using client, with every entity in
// namespace (empty for the default namespace).
func NewUserTokenStore(client *datastore.Client, namespace string) *GAEUserTokenStore {
	return &GAEUserTokenStore{client: client, namespace: namespace}
}

// errUserTokenKeyMismatch means an entity's fields name another key
// than the one it is stored under. It can only come from a write that
// bypassed this store.
var errUserTokenKeyMismatch = errors.New("gae: user token entity names a different key")

func (s *GAEUserTokenStore) key(provider, subject string) *datastore.Key {
	sum := sha256.Sum256([]byte(provider + "\x00" + subject))
	k := datastore.NameKey(KindUserToken, hex.EncodeToString(sum[:]), nil)
	k.Namespace = s.namespace
	return k
}

// GetUserToken returns the record, or outbound.ErrUserTokenNotFound
// when no entity has the key (datastore.ErrNoSuchEntity is mapped to
// it). Other Datastore errors pass through.
func (s *GAEUserTokenStore) GetUserToken(ctx context.Context, req *outbound.GetUserTokenRequest) (*outbound.GetUserTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserToken: req is required")
	}
	var e UserTokenEntity
	err := s.client.Get(ctx, s.key(req.Provider, req.Subject), &e)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return nil, outbound.ErrUserTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	if e.Provider != req.Provider || e.Subject != req.Subject {
		return nil, errUserTokenKeyMismatch
	}
	return &outbound.GetUserTokenResponse{Record: &outbound.UserTokenRecord{
		Provider: e.Provider, Subject: e.Subject, Sealed: e.Sealed, Version: e.Version, UpdatedAt: e.UpdatedAt,
	}}, nil
}

// PutUserToken writes if the stored version equals ExpectedVersion (zero
// meaning no entity exists), and answers outbound.ErrVersionConflict
// otherwise. The Get, the comparison and the Put run in one transaction.
// Datastore retries a transaction that collides with another; the retry
// reads the winner's version and returns ErrVersionConflict. If the
// retries run out, datastore.ErrConcurrentTransaction is mapped to
// ErrVersionConflict too, since another writer won.
func (s *GAEUserTokenStore) PutUserToken(ctx context.Context, req *outbound.PutUserTokenRequest) (*outbound.PutUserTokenResponse, error) {
	if req == nil || req.Provider == "" || req.Subject == "" {
		return nil, fmt.Errorf("PutUserToken: provider and subject are required")
	}
	key := s.key(req.Provider, req.Subject)
	next := req.ExpectedVersion + 1
	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var cur UserTokenEntity
		var have int64
		switch err := tx.Get(key, &cur); {
		case err == nil:
			if cur.Provider != req.Provider || cur.Subject != req.Subject {
				return errUserTokenKeyMismatch
			}
			have = cur.Version
		case !errors.Is(err, datastore.ErrNoSuchEntity):
			return err
		}
		if have != req.ExpectedVersion {
			return outbound.ErrVersionConflict
		}
		_, err := tx.Put(key, &UserTokenEntity{
			Provider: req.Provider, Subject: req.Subject, Sealed: req.Sealed, Version: next, UpdatedAt: time.Now(),
		})
		return err
	})
	if errors.Is(err, datastore.ErrConcurrentTransaction) {
		return nil, outbound.ErrVersionConflict
	}
	if err != nil {
		return nil, err
	}
	return &outbound.PutUserTokenResponse{Version: next}, nil
}

// DeleteUserToken removes the entity. Datastore deletes of a missing key
// succeed, so disconnecting twice is safe.
func (s *GAEUserTokenStore) DeleteUserToken(ctx context.Context, req *outbound.DeleteUserTokenRequest) (*outbound.DeleteUserTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteUserToken: req is required")
	}
	if err := s.client.Delete(ctx, s.key(req.Provider, req.Subject)); err != nil {
		return nil, err
	}
	return &outbound.DeleteUserTokenResponse{}, nil
}

var _ outbound.UserTokenStore = (*GAEUserTokenStore)(nil)
