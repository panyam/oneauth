//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/core"
	"google.golang.org/api/iterator"
)

const KindAppRegistration = "AppRegistration"

// AppRegistrationEntity is the Datastore entity for app registrations.
// All non-key fields are noindex — we only ever look up by the entity key
// (client_id), and Datastore's 1500-byte per-property index limit would
// reject long values like a registration_client_uri or many redirect_uris.
type AppRegistrationEntity struct {
	Key                       *datastore.Key `datastore:"__key__"`
	ClientID                  string         `datastore:"client_id,noindex"`
	ClientDomain              string         `datastore:"client_domain,noindex"`
	SigningAlg                string         `datastore:"signing_alg,noindex"`
	AuthorizationDetailsTypes []string       `datastore:"authorization_details_types,noindex"`
	CreatedAt                 int64          `datastore:"created_at,noindex"` // unix nanos — keeps Datastore microsecond truncation out of the equality check
	Revoked                   bool           `datastore:"revoked,noindex"`

	ClientName              string   `datastore:"client_name,noindex"`
	ClientURI               string   `datastore:"client_uri,noindex"`
	RedirectURIs            []string `datastore:"redirect_uris,noindex"`
	GrantTypes              []string `datastore:"grant_types,noindex"`
	Scope                   string   `datastore:"scope,noindex"`
	TokenEndpointAuthMethod string   `datastore:"token_endpoint_auth_method,noindex"`

	RegistrationAccessToken string `datastore:"registration_access_token,noindex"`
	RegistrationClientURI   string `datastore:"registration_client_uri,noindex"`
}

// GAEAppStore implements core.AppRegistrationStore using Google Cloud Datastore.
// Multi-node compatible — Datastore is the shared source of truth — and slots
// into stores/gae/ alongside GAEKeyStore and GAEKidStore.
type GAEAppStore struct {
	client    *datastore.Client
	namespace string
}

var _ core.AppRegistrationStore = (*GAEAppStore)(nil)

// NewAppStore creates a new Datastore-backed AppRegistrationStore.
func NewAppStore(client *datastore.Client, namespace string) *GAEAppStore {
	return &GAEAppStore{
		client:    client,
		namespace: namespace,
	}
}

func (s *GAEAppStore) appKey(clientID string) *datastore.Key {
	key := datastore.NameKey(KindAppRegistration, clientID, nil)
	key.Namespace = s.namespace
	return key
}

// SaveApp inserts or replaces the registration for req.App.ClientID. Empty
// client_id is rejected with the same error message as InMemoryAppStore /
// FSAppStore / GORMAppStore so the shared appstoretest contract passes
// uniformly across backends.
func (s *GAEAppStore) SaveApp(ctx context.Context, req *core.SaveAppRequest) (*core.SaveAppResponse, error) {
	if req == nil || req.App == nil || req.App.ClientID == "" {
		return nil, errors.New("AppRegistration.ClientID required")
	}
	entity := appRegToEntity(s.appKey(req.App.ClientID), req.App)
	if _, err := s.client.Put(ctx, entity.Key, entity); err != nil {
		return nil, err
	}
	return &core.SaveAppResponse{}, nil
}

// GetApp returns the registration for req.ClientID, or core.ErrAppNotFound
// when the entity is absent. Other Datastore errors (network, auth, quota)
// surface unwrapped so callers can distinguish "not registered" from
// "infrastructure problem."
func (s *GAEAppStore) GetApp(ctx context.Context, req *core.GetAppRequest) (*core.GetAppResponse, error) {
	if req == nil {
		return nil, errors.New("GetApp: req is required")
	}
	var entity AppRegistrationEntity
	if err := s.client.Get(ctx, s.appKey(req.ClientID), &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, core.ErrAppNotFound
		}
		return nil, err
	}
	return &core.GetAppResponse{App: entityToAppReg(&entity)}, nil
}

// ListApps returns every registration in this namespace. Order is unspecified
// (Datastore queries without an explicit Order return results in key order,
// which is implementation-defined). Returns an empty slice (not an error)
// for an empty namespace, matching the other backends' "fresh store has no
// apps" shape.
func (s *GAEAppStore) ListApps(ctx context.Context, req *core.ListAppsRequest) (*core.ListAppsResponse, error) {
	q := datastore.NewQuery(KindAppRegistration).Namespace(s.namespace)
	it := s.client.Run(ctx, q)
	out := []*core.AppRegistration{}
	for {
		var entity AppRegistrationEntity
		_, err := it.Next(&entity)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ListApps iterate: %w", err)
		}
		out = append(out, entityToAppReg(&entity))
	}
	return &core.ListAppsResponse{Apps: out}, nil
}

// DeleteApp removes the registration for req.ClientID. Returns
// core.ErrAppNotFound if no such registration exists, matching the
// other AppRegistrationStore backends — Datastore's bare Delete is
// idempotent and silently succeeds on missing keys, so we Get-then-Delete
// to honor the contract (the conformance suite's TestDeleteNonexistent
// asserts on ErrAppNotFound).
func (s *GAEAppStore) DeleteApp(ctx context.Context, req *core.DeleteAppRequest) (*core.DeleteAppResponse, error) {
	if req == nil {
		return nil, errors.New("DeleteApp: req is required")
	}
	key := s.appKey(req.ClientID)
	var probe AppRegistrationEntity
	if err := s.client.Get(ctx, key, &probe); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, core.ErrAppNotFound
		}
		return nil, err
	}
	if err := s.client.Delete(ctx, key); err != nil {
		return nil, err
	}
	return &core.DeleteAppResponse{}, nil
}

func appRegToEntity(key *datastore.Key, app *core.AppRegistration) *AppRegistrationEntity {
	return &AppRegistrationEntity{
		Key:                       key,
		ClientID:                  app.ClientID,
		ClientDomain:              app.ClientDomain,
		SigningAlg:                app.SigningAlg,
		AuthorizationDetailsTypes: app.AuthorizationDetailsTypes,
		CreatedAt:                 app.CreatedAt.UnixNano(),
		Revoked:                   app.Revoked,
		ClientName:                app.ClientName,
		ClientURI:                 app.ClientURI,
		RedirectURIs:              app.RedirectURIs,
		GrantTypes:                app.GrantTypes,
		Scope:                     app.Scope,
		TokenEndpointAuthMethod:   app.TokenEndpointAuthMethod,
		RegistrationAccessToken:   app.RegistrationAccessToken,
		RegistrationClientURI:     app.RegistrationClientURI,
	}
}

func entityToAppReg(e *AppRegistrationEntity) *core.AppRegistration {
	return &core.AppRegistration{
		ClientID:                  e.ClientID,
		ClientDomain:              e.ClientDomain,
		SigningAlg:                e.SigningAlg,
		AuthorizationDetailsTypes: e.AuthorizationDetailsTypes,
		CreatedAt:                 unixNanosToTime(e.CreatedAt),
		Revoked:                   e.Revoked,
		ClientName:                e.ClientName,
		ClientURI:                 e.ClientURI,
		RedirectURIs:              e.RedirectURIs,
		GrantTypes:                e.GrantTypes,
		Scope:                     e.Scope,
		TokenEndpointAuthMethod:   e.TokenEndpointAuthMethod,
		RegistrationAccessToken:   e.RegistrationAccessToken,
		RegistrationClientURI:     e.RegistrationClientURI,
	}
}

// unixNanosToTime restores time.Time from a unix-nanosecond integer round-trip.
// Returns the zero time when nanos == 0 so a never-set CreatedAt does not become
// 1970-01-01 (matches GORM's NULL-time behavior and the InMemory/FS zero default).
func unixNanosToTime(nanos int64) time.Time {
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}
