//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/core"
)

// KindAuthorizationCode is the Datastore kind for authorization codes.
const KindAuthorizationCode = "AuthorizationCode"

// AuthorizationCodeEntity is the Datastore entity for one RFC 6749 §4.1
// authorization code.
//
//   - The key name is the hex digest from core.AtRestKey(code), and Record
//     leaves the code out, so a copy of the datastore can't redeem a code.
//   - Record is the core.AuthorizationCode as JSON. JSON keeps nanosecond
//     times (Datastore truncates time.Time to microseconds) and takes new
//     fields without a schema change. It is unindexed.
//   - RetainUntil is the record's RetainUntil in unix nanos, indexed for
//     CleanupExpired's range query.
type AuthorizationCodeEntity struct {
	Record      []byte `datastore:"record,noindex"`
	RetainUntil int64  `datastore:"retain_until"`
}

// GAEAuthorizationCodeStore implements core.AuthorizationCodeStore on
// Cloud Datastore. Consume and RecordTokens each run in one transaction,
// so whichever of two racing calls commits second sees the other's write,
// across replicas, as reuse detection needs.
type GAEAuthorizationCodeStore struct {
	client    *datastore.Client
	namespace string
}

var _ core.AuthorizationCodeStore = (*GAEAuthorizationCodeStore)(nil)

// NewAuthorizationCodeStore returns a store using client, with every
// entity in namespace (empty for the default namespace).
func NewAuthorizationCodeStore(client *datastore.Client, namespace string) *GAEAuthorizationCodeStore {
	return &GAEAuthorizationCodeStore{client: client, namespace: namespace}
}

func (s *GAEAuthorizationCodeStore) key(code string) *datastore.Key {
	k := datastore.NameKey(KindAuthorizationCode, strings.TrimPrefix(core.AtRestKey(code), "sha256:"), nil)
	k.Namespace = s.namespace
	return k
}

func codeEntity(c *core.AuthorizationCode) (*AuthorizationCodeEntity, error) {
	out := *c
	out.Code = ""
	b, err := json.Marshal(&out)
	if err != nil {
		return nil, err
	}
	return &AuthorizationCodeEntity{Record: b, RetainUntil: c.RetainUntil().UnixNano()}, nil
}

func entityCode(e *AuthorizationCodeEntity, code string) (*core.AuthorizationCode, error) {
	var c core.AuthorizationCode
	if err := json.Unmarshal(e.Record, &c); err != nil {
		return nil, fmt.Errorf("gae: authorization code record: %w", err)
	}
	c.Code = code
	return &c, nil
}

// CreateAuthorizationCode stores a new code. The existence check and the
// Put share a transaction. A code that already exists is a generic error,
// matching the in-memory store: the caller drew it from a CSPRNG.
func (s *GAEAuthorizationCodeStore) CreateAuthorizationCode(ctx context.Context, req *core.CreateAuthorizationCodeRequest) (*core.CreateAuthorizationCodeResponse, error) {
	if req == nil || req.Code == nil || req.Code.Code == "" {
		return nil, errors.New("CreateAuthorizationCode: code is required")
	}
	e, err := codeEntity(req.Code)
	if err != nil {
		return nil, err
	}
	key := s.key(req.Code.Code)
	_, err = s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var probe AuthorizationCodeEntity
		switch err := tx.Get(key, &probe); {
		case err == nil:
			return errors.New("CreateAuthorizationCode: code collision")
		case !errors.Is(err, datastore.ErrNoSuchEntity):
			return err
		}
		_, err := tx.Put(key, e)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &core.CreateAuthorizationCodeResponse{}, nil
}

// GetAuthorizationCode returns the record or
// core.ErrAuthorizationCodeNotFound (datastore.ErrNoSuchEntity maps to
// it). It doesn't filter by expiry.
func (s *GAEAuthorizationCodeStore) GetAuthorizationCode(ctx context.Context, req *core.GetAuthorizationCodeRequest) (*core.GetAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	var e AuthorizationCodeEntity
	if err := s.client.Get(ctx, s.key(req.Code), &e); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return nil, core.ErrAuthorizationCodeNotFound
		}
		return nil, err
	}
	c, err := entityCode(&e, req.Code)
	if err != nil {
		return nil, err
	}
	return &core.GetAuthorizationCodeResponse{Code: c}, nil
}

// update runs fn on code's record inside one transaction and writes the
// record back. fn returns the response error to pass through after the
// write (core.ErrAuthorizationCodeUsed), so the write still commits. A
// missing code is core.ErrAuthorizationCodeNotFound.
//
// Racing redemptions of one code contend on its entity by design, so the
// transaction gets contendedTxAttempts rather than Datastore's default 3.
func (s *GAEAuthorizationCodeStore) update(ctx context.Context, code string, fn func(c *core.AuthorizationCode) error) error {
	key := s.key(code)
	var passThrough error
	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		passThrough = nil
		var e AuthorizationCodeEntity
		if err := tx.Get(key, &e); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return core.ErrAuthorizationCodeNotFound
			}
			return err
		}
		c, err := entityCode(&e, code)
		if err != nil {
			return err
		}
		passThrough = fn(c)
		next, err := codeEntity(c)
		if err != nil {
			return err
		}
		_, err = tx.Put(key, next)
		return err
	}, datastore.MaxAttempts(contendedTxAttempts))
	if err != nil {
		return err
	}
	return passThrough
}

// ConsumeAuthorizationCode marks an unused code used and returns the
// record as it was. For a used code it sets ReuseDetected and returns
// core.ErrAuthorizationCodeUsed with the record, whose Issued* fields
// name the tokens to revoke. A missing code is
// core.ErrAuthorizationCodeNotFound.
func (s *GAEAuthorizationCodeStore) ConsumeAuthorizationCode(ctx context.Context, req *core.ConsumeAuthorizationCodeRequest) (*core.ConsumeAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	var before core.AuthorizationCode
	err := s.update(ctx, req.Code, func(c *core.AuthorizationCode) error {
		before = *c
		if c.IsUsed() {
			c.ReuseDetected = true
			return core.ErrAuthorizationCodeUsed
		}
		c.UsedAt = time.Now()
		return nil
	})
	if errors.Is(err, core.ErrAuthorizationCodeUsed) {
		return &core.ConsumeAuthorizationCodeResponse{Code: &before}, err
	}
	if err != nil {
		return nil, err
	}
	return &core.ConsumeAuthorizationCodeResponse{Code: &before}, nil
}

// RecordAuthorizationCodeTokens stores the tokens a redemption minted and
// reports ReuseDetected, read in the same transaction. A missing code is
// core.ErrAuthorizationCodeNotFound.
func (s *GAEAuthorizationCodeStore) RecordAuthorizationCodeTokens(ctx context.Context, req *core.RecordAuthorizationCodeTokensRequest) (*core.RecordAuthorizationCodeTokensResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	reuse := false
	err := s.update(ctx, req.Code, func(c *core.AuthorizationCode) error {
		c.IssuedTokenID = req.TokenID
		c.IssuedTokenExpiresAt = req.TokenExpiresAt
		c.IssuedRefreshFamily = req.RefreshFamily
		reuse = c.ReuseDetected
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &core.RecordAuthorizationCodeTokensResponse{ReuseDetected: reuse}, nil
}

// DeleteAuthorizationCode removes the entity, or returns
// core.ErrAuthorizationCodeNotFound when there is none. Datastore deletes
// of a missing key succeed silently, so the existence check and the
// delete share a transaction.
func (s *GAEAuthorizationCodeStore) DeleteAuthorizationCode(ctx context.Context, req *core.DeleteAuthorizationCodeRequest) (*core.DeleteAuthorizationCodeResponse, error) {
	if req == nil || req.Code == "" {
		return nil, core.ErrAuthorizationCodeNotFound
	}
	key := s.key(req.Code)
	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var e AuthorizationCodeEntity
		if err := tx.Get(key, &e); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return core.ErrAuthorizationCodeNotFound
			}
			return err
		}
		return tx.Delete(key)
	})
	if err != nil {
		return nil, err
	}
	return &core.DeleteAuthorizationCodeResponse{}, nil
}

// CleanupExpired removes every record whose RetainUntil has passed. The
// query is keys-only on the indexed retain_until, and deletes go in
// batches of 500, Datastore's cap per DeleteMulti.
func (s *GAEAuthorizationCodeStore) CleanupExpired(ctx context.Context, _ *core.CleanupExpiredAuthorizationCodesRequest) (*core.CleanupExpiredAuthorizationCodesResponse, error) {
	n, err := deleteExpired(ctx, s.client, s.namespace, KindAuthorizationCode, "retain_until")
	if err != nil {
		return nil, err
	}
	return &core.CleanupExpiredAuthorizationCodesResponse{Removed: n}, nil
}

// deleteExpired deletes every entity of kind in namespace whose indexed
// int64 unix-nanos property field is at or before now, and returns how
// many it deleted.
func deleteExpired(ctx context.Context, client *datastore.Client, namespace, kind, field string) (int, error) {
	q := datastore.NewQuery(kind).Namespace(namespace).FilterField(field, "<=", time.Now().UnixNano()).KeysOnly()
	keys, err := client.GetAll(ctx, q, nil)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(keys); i += 500 {
		end := min(i+500, len(keys))
		if err := client.DeleteMulti(ctx, keys[i:end]); err != nil {
			return i, err
		}
	}
	return len(keys), nil
}
