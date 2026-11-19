//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/core"
)

// KindConsent is the Datastore kind for consent grants.
const KindConsent = "Consent"

// ConsentEntity is the Datastore entity for one core.ConsentGrant.
//
//   - The key name is the hex SHA-256 of subject + "\x00" + client_id, so
//     any characters in either are safe and each pair gets one entity.
//   - Record is the grant as JSON, subject and client_id included, so the
//     times round-trip at full precision rather than Datastore's
//     microseconds. It is unindexed.
type ConsentEntity struct {
	Record []byte `datastore:"record,noindex"`
}

// errConsentKeyMismatch means the entity under a key holds another
// subject's or client's grant, which only a write that bypassed this
// store can cause.
var errConsentKeyMismatch = errors.New("gae: consent entity names a different key")

// GAEConsentStore implements core.ConsentStore on Cloud Datastore. Every
// node reads the same entities, so an approval given through one node lets
// a later prompt=none request on any node skip the consent screen.
type GAEConsentStore struct {
	client    *datastore.Client
	namespace string
}

var _ core.ConsentStore = (*GAEConsentStore)(nil)

// NewConsentStore returns a store using client, with every entity in
// namespace (empty for the default namespace).
func NewConsentStore(client *datastore.Client, namespace string) *GAEConsentStore {
	return &GAEConsentStore{client: client, namespace: namespace}
}

func (s *GAEConsentStore) key(subject, clientID string) *datastore.Key {
	sum := sha256.Sum256([]byte(subject + "\x00" + clientID))
	k := datastore.NameKey(KindConsent, hex.EncodeToString(sum[:]), nil)
	k.Namespace = s.namespace
	return k
}

// SaveConsent puts req.Grant, replacing any grant for the same subject
// and client_id. A Datastore put is a whole-entity write, so two racing
// saves leave one of the two grants, never a mix. Empty subject or
// client_id is an error.
func (s *GAEConsentStore) SaveConsent(ctx context.Context, req *core.SaveConsentRequest) (*core.SaveConsentResponse, error) {
	if req == nil || req.Grant == nil {
		return nil, errors.New("SaveConsent: grant is required")
	}
	g := req.Grant
	if g.Subject == "" || g.ClientID == "" {
		return nil, errors.New("SaveConsent: subject and client_id are required")
	}
	b, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	if _, err := s.client.Put(ctx, s.key(g.Subject, g.ClientID), &ConsentEntity{Record: b}); err != nil {
		return nil, err
	}
	out := *g
	out.Scopes = slices.Clone(g.Scopes)
	return &core.SaveConsentResponse{Grant: &out}, nil
}

// GetConsent returns the stored grant, expired or not, or
// core.ErrConsentNotFound (datastore.ErrNoSuchEntity maps to it). An
// entity holding another key's grant is an error rather than a match.
// Other Datastore errors pass through.
func (s *GAEConsentStore) GetConsent(ctx context.Context, req *core.GetConsentRequest) (*core.GetConsentResponse, error) {
	if req == nil || req.Subject == "" || req.ClientID == "" {
		return nil, core.ErrConsentNotFound
	}
	var e ConsentEntity
	if err := s.client.Get(ctx, s.key(req.Subject, req.ClientID), &e); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return nil, core.ErrConsentNotFound
		}
		return nil, err
	}
	var g core.ConsentGrant
	if err := json.Unmarshal(e.Record, &g); err != nil {
		return nil, fmt.Errorf("gae: consent record: %w", err)
	}
	if g.Subject != req.Subject || g.ClientID != req.ClientID {
		return nil, errConsentKeyMismatch
	}
	return &core.GetConsentResponse{Grant: &g}, nil
}

// RevokeConsent deletes the entity. A Datastore delete of a missing key
// succeeds, so a second revoke is not an error.
func (s *GAEConsentStore) RevokeConsent(ctx context.Context, req *core.RevokeConsentRequest) (*core.RevokeConsentResponse, error) {
	if req == nil || req.Subject == "" || req.ClientID == "" {
		return &core.RevokeConsentResponse{}, nil
	}
	if err := s.client.Delete(ctx, s.key(req.Subject, req.ClientID)); err != nil {
		return nil, err
	}
	return &core.RevokeConsentResponse{}, nil
}
