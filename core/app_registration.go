package core

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// ErrAppNotFound is returned by AppRegistrationStore.GetApp and DeleteApp
// when the requested client_id does not exist.
var ErrAppNotFound = errors.New("app registration not found")

// AppRegistration holds metadata about a registered App (RFC 7591 client).
//
// Lives in core/ so storage backends (stores/fs, stores/gorm, stores/gae) can
// implement AppRegistrationStore without importing admin/. The DCR / RFC 7592
// management metadata fields are persisted starting in issue 165 so that the
// schema is stable as RFC 7592 management endpoints (issue 168/169/170) populate
// them. They may be empty for legacy registrations.
type AppRegistration struct {
	ClientID                  string    `json:"client_id"`
	ClientDomain              string    `json:"client_domain"`
	SigningAlg                string    `json:"signing_alg"`
	AuthorizationDetailsTypes []string  `json:"authorization_details_types,omitempty"` // RFC 9396
	CreatedAt                 time.Time `json:"created_at"`
	Revoked                   bool      `json:"revoked"`

	// RFC 7591 / 7592 client metadata (populated by DCR; see issue 157).
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`

	// RFC 7592 management credentials. Issued when the management protocol
	// is implemented (issue 168); empty for legacy registrations.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`

	// OIDC Back-Channel Logout 1.0 — per-client push endpoint. When set, the
	// AS POSTs a signed logout_token to BackchannelLogoutURI whenever a
	// session that touched this client is revoked (issue 261).
	// BackchannelLogoutSessionRequired toggles whether the logout_token MUST
	// carry a sid claim — true means the client tracks sessions per spec §2.2.
	// Empty BackchannelLogoutURI disables dispatch for this client.
	BackchannelLogoutURI             string `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required,omitempty"`

	// DPoPBoundAccessTokens is the RFC 9449 §5.2 client metadata: when
	// true, the token endpoint refuses this client's token requests that
	// carry no DPoP proof, so every token it receives is sender-constrained.
	// False leaves DPoP per-request opt-in for this client, unless
	// OneAuthConfig.RequireDPoP demands it of every client.
	DPoPBoundAccessTokens bool `json:"dpop_bound_access_tokens,omitempty"`

	// RequirePushedAuthorizationRequests is the RFC 9126 §6 client
	// metadata: when true, /authorize refuses this client's requests that
	// don't arrive through PAR, the per-client form of
	// AuthorizationHandler.RequirePushedRequests.
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests,omitempty"`

	// JWKSURI is the RFC 7591 §2 jwks_uri: where a private_key_jwt client
	// publishes its public keys. A client registered with it has no key in
	// the KeyStore; client authentication fetches the set and picks the key
	// by the assertion's kid, so the client rotates keys by publishing new
	// ones rather than re-registering (issue 507).
	JWKSURI string `json:"jwks_uri,omitempty"`

	// JWKS is an inline RFC 7591 §2 jwks, a JSON Web Key Set of public
	// keys. Only apiauth.CIMDAppStore sets it, from a client ID metadata
	// document (issue 532), and the client authenticator verifies that
	// client's private_key_jwt assertions with it. Stores never persist
	// it. A DCR client's inline keys go to the KeyStore instead.
	JWKS json.RawMessage `json:"-"`
	// TokenEndpointAuthSigningAlg is the OIDC Registration §2
	// token_endpoint_auth_signing_alg. When set, a jwks_uri client's
	// assertions must use this algorithm. Empty accepts any asymmetric
	// algorithm the selected key's type supports.
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`

	// LogoURI, PolicyURI and TOSURI are the OIDC Registration §2 display
	// metadata. The consent page shows the logo and links to the policy and
	// terms, so the user sees who is asking. Each is an https URL or empty.
	LogoURI   string `json:"logo_uri,omitempty"`
	PolicyURI string `json:"policy_uri,omitempty"`
	TOSURI    string `json:"tos_uri,omitempty"`

	// SubjectType is the OIDC Core §8 subject identifier type: "public"
	// (or empty) gives the client the user's own ID as sub, "pairwise" a
	// value derived from SectorIdentifier, so clients in different sectors
	// can't match up a user (issue 507).
	SubjectType string `json:"subject_type,omitempty"`
	// SectorIdentifierURI is the OIDC Registration §2 sector_identifier_uri
	// the client registered, if any, kept for echoing back.
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`

	// UserinfoSignedResponseAlg is the OIDC Registration §2
	// userinfo_signed_response_alg. When set, the userinfo endpoint
	// answers this client with a JWT signed by the AS key
	// (application/jwt, OIDC Core §5.3.2). Empty answers with plain JSON.
	UserinfoSignedResponseAlg string `json:"userinfo_signed_response_alg,omitempty"`
	// SectorIdentifier is the host a pairwise sub is derived from (OIDC
	// Core §8.1): the sector_identifier_uri's host, or the redirect URIs'
	// one host. Registration sets it; it must not change afterwards, or
	// the client's users get new subs.
	SectorIdentifier string `json:"sector_identifier,omitempty"`

	// ResponseTypes are the RFC 7591 §2 response_type values the client
	// may use at /authorize. Empty means ["code"], the default. The
	// implicit types "id_token" and "id_token token" appear only on a
	// server that allows implicit, for a client that registered them
	// (issue 507).
	ResponseTypes []string `json:"response_types,omitempty"`
}

// SaveAppRequest carries the registration to persist.
type SaveAppRequest struct {
	App *AppRegistration
}

// SaveAppResponse is empty; SaveApp returns only an error signal.
type SaveAppResponse struct{}

// GetAppRequest carries the client_id to look up.
type GetAppRequest struct {
	ClientID string
}

// GetAppResponse wraps the requested registration.
type GetAppResponse struct {
	App *AppRegistration
}

// ListAppsRequest is empty; ListApps takes no parameters.
type ListAppsRequest struct{}

// ListAppsResponse wraps every registration in the store. Order is unspecified.
type ListAppsResponse struct {
	Apps []*AppRegistration
}

// DeleteAppRequest carries the client_id to remove.
type DeleteAppRequest struct {
	ClientID string
}

// DeleteAppResponse is empty; DeleteApp returns only an error signal.
type DeleteAppResponse struct{}

// AppRegistrationStore persists app registration metadata.
//
// Source of truth for registered apps; admin.AppRegistrar holds a hot-path
// in-memory cache that is hydrated from the store on construction and updated
// on every write.
//
// Backends: InMemoryAppStore (below), FSAppStore (stores/fs/), GORMAppStore
// (stores/gorm/), and any future Datastore-backed implementation (issue 228).
type AppRegistrationStore interface {
	// SaveApp inserts or replaces the registration for req.App.ClientID.
	SaveApp(ctx context.Context, req *SaveAppRequest) (*SaveAppResponse, error)

	// GetApp returns the registration for req.ClientID, or ErrAppNotFound.
	GetApp(ctx context.Context, req *GetAppRequest) (*GetAppResponse, error)

	// ListApps returns every registration in the store. Order is unspecified.
	ListApps(ctx context.Context, req *ListAppsRequest) (*ListAppsResponse, error)

	// DeleteApp removes the registration for req.ClientID. Returns ErrAppNotFound
	// if no such registration exists.
	DeleteApp(ctx context.Context, req *DeleteAppRequest) (*DeleteAppResponse, error)
}

// InMemoryAppStore is a process-local AppRegistrationStore. State is lost on
// restart — suitable for tests and dev. Production deployments should use a
// persistent backend (FS, GORM, GAE).
type InMemoryAppStore struct {
	mu   sync.RWMutex
	apps map[string]*AppRegistration
}

// NewInMemoryAppStore returns an empty InMemoryAppStore.
func NewInMemoryAppStore() *InMemoryAppStore {
	return &InMemoryAppStore{apps: make(map[string]*AppRegistration)}
}

func (s *InMemoryAppStore) SaveApp(ctx context.Context, req *SaveAppRequest) (*SaveAppResponse, error) {
	if req == nil || req.App == nil || req.App.ClientID == "" {
		return nil, errors.New("AppRegistration.ClientID required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *req.App
	s.apps[req.App.ClientID] = &clone
	return &SaveAppResponse{}, nil
}

func (s *InMemoryAppStore) GetApp(ctx context.Context, req *GetAppRequest) (*GetAppResponse, error) {
	if req == nil {
		return nil, errors.New("GetApp: req is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	app, ok := s.apps[req.ClientID]
	if !ok {
		return nil, ErrAppNotFound
	}
	clone := *app
	return &GetAppResponse{App: &clone}, nil
}

func (s *InMemoryAppStore) ListApps(ctx context.Context, req *ListAppsRequest) (*ListAppsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*AppRegistration, 0, len(s.apps))
	for _, app := range s.apps {
		clone := *app
		out = append(out, &clone)
	}
	return &ListAppsResponse{Apps: out}, nil
}

func (s *InMemoryAppStore) DeleteApp(ctx context.Context, req *DeleteAppRequest) (*DeleteAppResponse, error) {
	if req == nil {
		return nil, errors.New("DeleteApp: req is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apps[req.ClientID]; !ok {
		return nil, ErrAppNotFound
	}
	delete(s.apps, req.ClientID)
	return &DeleteAppResponse{}, nil
}
