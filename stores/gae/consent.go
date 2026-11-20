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
	"time"

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
//   - Subject repeats the grant's subject as an indexed property, so
//     ListConsents finds a user's grants with an equality query. A
//     single-property filter uses Datastore's built-in index, so no
//     index.yaml entry is needed. Grants saved before the property
//     existed have none: GetConsent adds it when it reads one, and
//     BackfillConsentSubjects adds it to all of them (issue 526).
type ConsentEntity struct {
	Record  []byte `datastore:"record,noindex"`
	Subject string `datastore:"subject"`
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

var (
	_ core.ConsentStore  = (*GAEConsentStore)(nil)
	_ core.ConsentLister = (*GAEConsentStore)(nil)
)

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
	if _, err := s.client.Put(ctx, s.key(g.Subject, g.ClientID), &ConsentEntity{Record: b, Subject: g.Subject}); err != nil {
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
	if e.Subject == "" {
		// A grant saved before the subject property existed. Adding it
		// lets ListConsents find the grant; failing to is not this
		// read's problem.
		e.Subject = g.Subject
		_, _ = s.client.Put(ctx, s.key(g.Subject, g.ClientID), &e)
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

// ListConsents returns the subject's unexpired grants, sorted by
// client_id. It runs one equality query on the indexed subject property,
// then decodes each Record and drops expired grants and any whose key
// isn't the hash of the grant it holds, which GetConsent would refuse.
// The query is eventually consistent on Cloud Datastore, so a grant
// saved a moment ago can be missing from the list. Datastore errors pass
// through.
func (s *GAEConsentStore) ListConsents(ctx context.Context, req *core.ListConsentsRequest) (*core.ListConsentsResponse, error) {
	out := []*core.ConsentGrant{}
	if req == nil || req.Subject == "" {
		return &core.ListConsentsResponse{Grants: out}, nil
	}
	q := datastore.NewQuery(KindConsent).Namespace(s.namespace).FilterField("subject", "=", req.Subject)
	var entities []ConsentEntity
	keys, err := s.client.GetAll(ctx, q, &entities)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for i, e := range entities {
		var g core.ConsentGrant
		if err := json.Unmarshal(e.Record, &g); err != nil {
			return nil, fmt.Errorf("gae: consent record: %w", err)
		}
		if g.Subject != req.Subject || g.IsExpired(now) || keys[i].Name != s.key(g.Subject, g.ClientID).Name {
			continue
		}
		out = append(out, &g)
	}
	core.SortConsentGrants(out)
	return &core.ListConsentsResponse{Grants: out}, nil
}

// BackfillConsentSubjects adds the indexed subject property to every grant
// in the store's namespace saved before it existed, so ListConsents can
// find them, and returns how many it rewrote. It is idempotent, and safe
// to run while the store serves requests: a concurrent SaveConsent writes
// the same property. Run it once after upgrading past issue 516; GetConsent
// also repairs a grant whenever it reads one (issue 526).
func (s *GAEConsentStore) BackfillConsentSubjects(ctx context.Context) (int, error) {
	var entities []ConsentEntity
	keys, err := s.client.GetAll(ctx, datastore.NewQuery(KindConsent).Namespace(s.namespace), &entities)
	if err != nil {
		return 0, fmt.Errorf("gae: list consents: %w", err)
	}
	var putKeys []*datastore.Key
	var puts []*ConsentEntity
	for i := range entities {
		if entities[i].Subject != "" {
			continue
		}
		var g core.ConsentGrant
		if err := json.Unmarshal(entities[i].Record, &g); err != nil || g.Subject == "" {
			continue
		}
		if keys[i].Name != s.key(g.Subject, g.ClientID).Name {
			continue
		}
		entities[i].Subject = g.Subject
		putKeys = append(putKeys, keys[i])
		puts = append(puts, &entities[i])
	}
	// Datastore takes at most 500 entities per batch.
	for start := 0; start < len(puts); start += 500 {
		end := min(start+500, len(puts))
		if _, err := s.client.PutMulti(ctx, putKeys[start:end], puts[start:end]); err != nil {
			return start, fmt.Errorf("gae: backfill consent subjects: %w", err)
		}
	}
	return len(puts), nil
}
