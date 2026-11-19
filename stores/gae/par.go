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

// KindPushedAuthorizationRequest is the Datastore kind for RFC 9126 pushed
// authorization requests.
const KindPushedAuthorizationRequest = "PushedAuthorizationRequest"

// PushedAuthorizationRequestEntity is the Datastore entity for one pushed
// request.
//
//   - The key name is the hex digest from core.AtRestKey(request_uri), and
//     Record leaves the request_uri out.
//   - Record is the core.PushedAuthorizationRequest as JSON, so the
//     url.Values payload, extension parameters and authorization_details
//     included, round-trips verbatim. It is unindexed.
//   - ExpiresAt is unix nanos, indexed for the cleanup query.
type PushedAuthorizationRequestEntity struct {
	Record    []byte `datastore:"record,noindex"`
	ExpiresAt int64  `datastore:"expires_at"`
}

// GAEPushedAuthorizationRequestStore implements
// core.PushedAuthorizationRequestStore on Cloud Datastore. A request_uri
// minted by the node serving /par resolves on whichever node serves
// /authorize, and Consume's check-and-mark is one transaction, so exactly
// one approval spends a request across replicas.
type GAEPushedAuthorizationRequestStore struct {
	client    *datastore.Client
	namespace string
}

var _ core.PushedAuthorizationRequestStore = (*GAEPushedAuthorizationRequestStore)(nil)

// NewPushedAuthorizationRequestStore returns a store using client, with
// every entity in namespace (empty for the default namespace).
func NewPushedAuthorizationRequestStore(client *datastore.Client, namespace string) *GAEPushedAuthorizationRequestStore {
	return &GAEPushedAuthorizationRequestStore{client: client, namespace: namespace}
}

func (s *GAEPushedAuthorizationRequestStore) key(uri string) *datastore.Key {
	k := datastore.NameKey(KindPushedAuthorizationRequest, strings.TrimPrefix(core.AtRestKey(uri), "sha256:"), nil)
	k.Namespace = s.namespace
	return k
}

func pushedEntity(r *core.PushedAuthorizationRequest) (*PushedAuthorizationRequestEntity, error) {
	out := *r
	out.RequestURI = ""
	b, err := json.Marshal(&out)
	if err != nil {
		return nil, err
	}
	return &PushedAuthorizationRequestEntity{Record: b, ExpiresAt: r.ExpiresAt.UnixNano()}, nil
}

func entityPushed(e *PushedAuthorizationRequestEntity, uri string) (*core.PushedAuthorizationRequest, error) {
	var r core.PushedAuthorizationRequest
	if err := json.Unmarshal(e.Record, &r); err != nil {
		return nil, fmt.Errorf("gae: pushed request record: %w", err)
	}
	r.RequestURI = uri
	return &r, nil
}

// CreatePushedAuthorizationRequest stores a new request and returns it.
// The existence check and the Put share a transaction; a request_uri that
// already exists is a generic error, matching the in-memory store.
func (s *GAEPushedAuthorizationRequestStore) CreatePushedAuthorizationRequest(ctx context.Context, req *core.CreatePushedAuthorizationRequestRequest) (*core.CreatePushedAuthorizationRequestResponse, error) {
	if req == nil || req.Request == nil || req.Request.RequestURI == "" {
		return nil, errors.New("CreatePushedAuthorizationRequest: request_uri is required")
	}
	r := req.Request
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	e, err := pushedEntity(r)
	if err != nil {
		return nil, err
	}
	key := s.key(r.RequestURI)
	_, err = s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var probe PushedAuthorizationRequestEntity
		switch err := tx.Get(key, &probe); {
		case err == nil:
			return errors.New("CreatePushedAuthorizationRequest: request_uri collision")
		case !errors.Is(err, datastore.ErrNoSuchEntity):
			return err
		}
		_, err := tx.Put(key, e)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &core.CreatePushedAuthorizationRequestResponse{Request: r}, nil
}

// GetPushedAuthorizationRequest returns the record or
// core.ErrPushedRequestNotFound (datastore.ErrNoSuchEntity maps to it). It
// doesn't filter by expiry or consumption.
func (s *GAEPushedAuthorizationRequestStore) GetPushedAuthorizationRequest(ctx context.Context, req *core.GetPushedAuthorizationRequestRequest) (*core.GetPushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	var e PushedAuthorizationRequestEntity
	if err := s.client.Get(ctx, s.key(req.RequestURI), &e); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return nil, core.ErrPushedRequestNotFound
		}
		return nil, err
	}
	r, err := entityPushed(&e, req.RequestURI)
	if err != nil {
		return nil, err
	}
	return &core.GetPushedAuthorizationRequestResponse{Request: r}, nil
}

// ConsumePushedAuthorizationRequest marks the request used in one
// transaction and keeps the entity, so a replay reads back as used rather
// than unknown. Consumed is true for exactly one caller. Racing approvals
// contend on the entity by design, so the transaction gets
// contendedTxAttempts. A missing request is core.ErrPushedRequestNotFound.
func (s *GAEPushedAuthorizationRequestStore) ConsumePushedAuthorizationRequest(ctx context.Context, req *core.ConsumePushedAuthorizationRequestRequest) (*core.ConsumePushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	key := s.key(req.RequestURI)
	consumed := false
	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		consumed = false
		var e PushedAuthorizationRequestEntity
		if err := tx.Get(key, &e); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return core.ErrPushedRequestNotFound
			}
			return err
		}
		r, err := entityPushed(&e, req.RequestURI)
		if err != nil {
			return err
		}
		if r.Consumed {
			return nil
		}
		r.Consumed = true
		next, err := pushedEntity(r)
		if err != nil {
			return err
		}
		if _, err := tx.Put(key, next); err != nil {
			return err
		}
		consumed = true
		return nil
	}, datastore.MaxAttempts(contendedTxAttempts))
	if err != nil {
		return nil, err
	}
	return &core.ConsumePushedAuthorizationRequestResponse{Consumed: consumed}, nil
}

// DeletePushedAuthorizationRequest removes the entity, or returns
// core.ErrPushedRequestNotFound when there is none. The existence check
// and the delete share a transaction, since a Datastore delete of a
// missing key succeeds silently.
func (s *GAEPushedAuthorizationRequestStore) DeletePushedAuthorizationRequest(ctx context.Context, req *core.DeletePushedAuthorizationRequestRequest) (*core.DeletePushedAuthorizationRequestResponse, error) {
	if req == nil || req.RequestURI == "" {
		return nil, core.ErrPushedRequestNotFound
	}
	key := s.key(req.RequestURI)
	_, err := s.client.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var e PushedAuthorizationRequestEntity
		if err := tx.Get(key, &e); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return core.ErrPushedRequestNotFound
			}
			return err
		}
		return tx.Delete(key)
	})
	if err != nil {
		return nil, err
	}
	return &core.DeletePushedAuthorizationRequestResponse{}, nil
}

// CleanupExpiredPushedRequests removes every request past its ExpiresAt,
// consumed or not, so used requests don't pile up.
func (s *GAEPushedAuthorizationRequestStore) CleanupExpiredPushedRequests(ctx context.Context, _ *core.CleanupExpiredPushedRequestsRequest) (*core.CleanupExpiredPushedRequestsResponse, error) {
	n, err := deleteExpired(ctx, s.client, s.namespace, KindPushedAuthorizationRequest, "expires_at")
	if err != nil {
		return nil, err
	}
	return &core.CleanupExpiredPushedRequestsResponse{Removed: n}, nil
}
