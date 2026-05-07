package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// AppRegistration holds metadata about a registered App.
//
// The DCR / RFC 7592 fields below (ClientName, ClientURI, RedirectURIs,
// GrantTypes, Scope, TokenEndpointAuthMethod, RegistrationAccessToken,
// RegistrationClientURI) are persisted starting in issue #165 so that
// the schema is stable when issue #157 (RFC 7592 Management) populates
// them. They may be empty for apps registered via the legacy
// /apps/register endpoint.
type AppRegistration struct {
	ClientID                  string    `json:"client_id"`
	ClientDomain              string    `json:"client_domain"`
	SigningAlg                string    `json:"signing_alg"`
	MaxRooms                  int       `json:"max_rooms,omitempty"`
	MaxMsgRate                float64   `json:"max_msg_rate,omitempty"`
	AuthorizationDetailsTypes []string  `json:"authorization_details_types,omitempty"` // RFC 9396
	CreatedAt                 time.Time `json:"created_at"`
	Revoked                   bool      `json:"revoked"`

	// RFC 7591 / 7592 client metadata (populated by DCR; see #157).
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`

	// RFC 7592 management credentials. Issued when the management protocol
	// is implemented (#168); empty for legacy registrations.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// AppRegistrar is an embeddable HTTP handler for App registration CRUD.
// Mount it on any admin service's mux to let apps register and obtain signing credentials.
// Create with NewAppRegistrar() (in-memory store) or NewAppRegistrarWithStore.
type AppRegistrar struct {
	KeyStore keys.KeyStorage
	Auth     AdminAuth

	// KidStore retains old keys during rotation grace periods so that
	// in-flight tokens signed with the previous key remain verifiable.
	// If nil, rotation replaces the key immediately with no grace period.
	KidStore *keys.KidStore

	// DefaultGracePeriod is the default grace period for key rotation
	// when not specified in the request. Defaults to 24h.
	DefaultGracePeriod time.Duration

	// Store persists app registration metadata. It is the source of truth;
	// the apps map below is a hot-path cache hydrated on construction and
	// updated synchronously on every write.
	Store AppRegistrationStore

	mu   sync.RWMutex
	apps map[string]*AppRegistration
}

// NewAppRegistrar creates an AppRegistrar backed by an in-memory store.
// Equivalent to NewAppRegistrarWithStore(keyStore, auth, NewInMemoryAppStore()).
//
// For deployments that need registrations to survive restart, use
// NewAppRegistrarWithStore with a persistent backend (FSAppStore, GORMAppStore).
func NewAppRegistrar(keyStore keys.KeyStorage, auth AdminAuth) *AppRegistrar {
	return NewAppRegistrarWithStore(keyStore, auth, NewInMemoryAppStore())
}

// NewAppRegistrarWithStore creates an AppRegistrar backed by the given store.
// Existing registrations in the store are loaded into the in-memory cache so
// that subsequent reads (RLockApps, GET /apps) reflect the persisted state
// immediately after construction.
//
// If store.ListApps returns an error during hydration, the AppRegistrar is
// returned with an empty cache; subsequent writes proceed normally. (We do
// not panic — a transient store error at startup should not crash the host
// process. The error is intentionally swallowed here since there is no
// caller-visible context to report it through; callers wanting strict
// startup semantics should call store.ListApps themselves first.)
func NewAppRegistrarWithStore(keyStore keys.KeyStorage, auth AdminAuth, store AppRegistrationStore) *AppRegistrar {
	r := &AppRegistrar{
		KeyStore: keyStore,
		Auth:     auth,
		Store:    store,
		apps:     make(map[string]*AppRegistration),
	}
	if existing, err := store.ListApps(); err == nil {
		for _, app := range existing {
			clone := *app
			r.apps[app.ClientID] = &clone
		}
	}
	return r
}

// SaveRegistration persists the registration to the store and updates the
// in-memory cache. Used by handleRegister, DCRHandler, and (in #157) the
// RFC 7592 management endpoints. If the store write fails, the cache is
// not updated and the error is returned.
func (h *AppRegistrar) SaveRegistration(reg *AppRegistration) error {
	if err := h.Store.SaveApp(reg); err != nil {
		return err
	}
	h.mu.Lock()
	clone := *reg
	h.apps[reg.ClientID] = &clone
	h.mu.Unlock()
	return nil
}

// GetRegistration implements ClientRegistrationManager. It returns the
// RFC 7591 registration for req.ClientID iff req.AccessToken matches the
// stored registration_access_token. Returns ErrUnauthorized for every
// failure mode — wrong/missing token, unknown client_id, or a registration
// that lacks a management token (e.g., a legacy /apps/register entry) — so
// the management endpoint cannot be used to probe for valid client_ids.
//
// The returned DCRResponse intentionally omits client_secret. RFC 7592 §3
// permits but does not require echoing the secret on read; re-emitting
// symmetric credentials on every read enlarges the disclosure window if the
// registration access token is ever logged or proxied. Clients that lose
// the secret can rotate via PUT (#169).
//
// ctx is currently unused but threaded through for cancellation / deadline
// propagation once stores grow async ops, and for parity with the rest of
// the manager interface.
func (h *AppRegistrar) GetRegistration(ctx context.Context, req *GetRegistrationRequest) (*GetRegistrationResponse, error) {
	if req == nil || req.ClientID == "" || req.AccessToken == "" {
		return nil, ErrUnauthorized
	}
	reg, err := h.Store.GetApp(req.ClientID)
	if err != nil || reg == nil {
		return nil, ErrUnauthorized
	}
	if reg.RegistrationAccessToken == "" {
		return nil, ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(reg.RegistrationAccessToken), []byte(req.AccessToken)) != 1 {
		return nil, ErrUnauthorized
	}
	return &GetRegistrationResponse{
		Registration: &DCRResponse{
			ClientID:                  reg.ClientID,
			ClientIDIssuedAt:          reg.CreatedAt.Unix(),
			ClientSecretExpiresAt:     0,
			ClientName:                reg.ClientName,
			ClientURI:                 reg.ClientURI,
			RedirectURIs:              reg.RedirectURIs,
			GrantTypes:                reg.GrantTypes,
			TokenEndpointAuthMethod:   reg.TokenEndpointAuthMethod,
			Scope:                     reg.Scope,
			AuthorizationDetailsTypes: reg.AuthorizationDetailsTypes,
			RegistrationAccessToken:   reg.RegistrationAccessToken,
			RegistrationClientURI:     reg.RegistrationClientURI,
		},
	}, nil
}

// UpdateRegistration implements ClientRegistrationManager (RFC 7592 §2.2).
// It performs a full replacement of the editable metadata fields and rotates
// the registration_access_token; the new token is returned in the response.
// The old token becomes invalid as soon as SaveRegistration succeeds.
//
// Editable fields (overwritten from req.Metadata on success): ClientName,
// ClientURI, RedirectURIs, GrantTypes, Scope, AuthorizationDetailsTypes,
// ClientDomain (derived from ClientURI / ClientName, mirroring DCRHandler's
// logic).
//
// Locked fields (return ErrInvalidClientMetadata on attempted change):
//   - TokenEndpointAuthMethod — would require re-keying; out of scope for #169.
// Locked fields (silently retained):
//   - SigningAlg, ClientID, CreatedAt, RegistrationClientURI, the key material
//     in KeyStore.
//
// req.Metadata is treated as RFC 7591 client metadata; req.Metadata.JWKS is
// currently ignored (auth-method changes are rejected, so the JWKS cannot
// usefully change either).
//
// ctx is currently unused but threaded through for cancellation / deadline
// propagation once stores grow async ops, and for parity with the rest of
// the manager interface.
func (h *AppRegistrar) UpdateRegistration(ctx context.Context, req *UpdateRegistrationRequest) (*UpdateRegistrationResponse, error) {
	if req == nil || req.ClientID == "" || req.AccessToken == "" || req.Metadata == nil {
		return nil, ErrUnauthorized
	}
	reg, err := h.Store.GetApp(req.ClientID)
	if err != nil || reg == nil {
		return nil, ErrUnauthorized
	}
	if reg.RegistrationAccessToken == "" {
		return nil, ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(reg.RegistrationAccessToken), []byte(req.AccessToken)) != 1 {
		return nil, ErrUnauthorized
	}

	// Authenticated — past this point, validation errors return
	// ErrInvalidClientMetadata so the wrapper can map to 400 instead of 401.
	// Auth method changes are out of scope for #169 (would require re-keying).
	md := req.Metadata
	if md.TokenEndpointAuthMethod != "" && md.TokenEndpointAuthMethod != reg.TokenEndpointAuthMethod {
		return nil, ErrInvalidClientMetadata
	}

	newToken, err := generateRegistrationAccessToken()
	if err != nil {
		return nil, err
	}

	// Replace the editable metadata fields. ClientDomain mirrors the derivation
	// in DCRHandler.ServeHTTP so callers see consistent behavior on register
	// and update.
	domain := md.ClientURI
	if domain == "" {
		domain = md.ClientName
	}
	reg.ClientName = md.ClientName
	reg.ClientURI = md.ClientURI
	reg.RedirectURIs = md.RedirectURIs
	reg.GrantTypes = md.GrantTypes
	reg.Scope = md.Scope
	reg.AuthorizationDetailsTypes = md.AuthorizationDetailsTypes
	reg.ClientDomain = domain
	reg.RegistrationAccessToken = newToken

	if err := h.SaveRegistration(reg); err != nil {
		return nil, err
	}
	return &UpdateRegistrationResponse{
		Registration: &DCRResponse{
			ClientID:                  reg.ClientID,
			ClientIDIssuedAt:          reg.CreatedAt.Unix(),
			ClientSecretExpiresAt:     0,
			ClientName:                reg.ClientName,
			ClientURI:                 reg.ClientURI,
			RedirectURIs:              reg.RedirectURIs,
			GrantTypes:                reg.GrantTypes,
			TokenEndpointAuthMethod:   reg.TokenEndpointAuthMethod,
			Scope:                     reg.Scope,
			AuthorizationDetailsTypes: reg.AuthorizationDetailsTypes,
			RegistrationAccessToken:   reg.RegistrationAccessToken,
			RegistrationClientURI:     reg.RegistrationClientURI,
		},
	}, nil
}

// DeleteRegistration implements ClientRegistrationManager (RFC 7592 §2.3).
// On success it removes the registration from the AppRegistrationStore (and
// the in-memory cache), and deletes the client's signing key from KeyStore
// so any tokens already issued under this client_id fail subsequent
// signature-validation — satisfying the spec requirement that "the
// authorization server MUST invalidate" all tokens for a deleted client.
//
// Failure ordering mirrors handleDeleteApp: we persist the deletion in the
// store first; only on success do we drop the cache entry and the KeyStore
// key. If the store write fails we return early without touching the
// in-memory cache or the credentials, so the registration remains
// authoritatively present (deletion can be retried).
//
// ctx is currently unused but threaded through for cancellation / deadline
// propagation once stores grow async ops.
func (h *AppRegistrar) DeleteRegistration(ctx context.Context, req *DeleteRegistrationRequest) (*DeleteRegistrationResponse, error) {
	if req == nil || req.ClientID == "" || req.AccessToken == "" {
		return nil, ErrUnauthorized
	}
	reg, err := h.Store.GetApp(req.ClientID)
	if err != nil || reg == nil {
		return nil, ErrUnauthorized
	}
	if reg.RegistrationAccessToken == "" {
		return nil, ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(reg.RegistrationAccessToken), []byte(req.AccessToken)) != 1 {
		return nil, ErrUnauthorized
	}

	// Persist deletion first. If the store write fails we leave the cache
	// and KeyStore intact so the client retains a known-consistent state
	// and the caller can retry; otherwise we'd leave dangling key material
	// without a registration to bind it.
	if err := h.Store.DeleteApp(req.ClientID); err != nil && err != ErrAppNotFound {
		return nil, err
	}

	h.mu.Lock()
	delete(h.apps, req.ClientID)
	h.mu.Unlock()

	// Invalidate the signing credentials. Errors here are non-fatal — the
	// registration is gone, which is the user-visible deletion contract;
	// a stranded key is at worst an internal cleanup concern (the KeyStore
	// entry is unreachable without an AppRegistration to point at it).
	_ = h.KeyStore.DeleteKey(req.ClientID)

	return &DeleteRegistrationResponse{}, nil
}

// RLockApps calls fn with a read-locked view of all registered apps.
func (h *AppRegistrar) RLockApps(fn func(map[string]*AppRegistration)) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	fn(h.apps)
}

// Handler returns an http.Handler for app registration endpoints.
// Includes both custom OneAuth API, RFC 7591 DCR, and RFC 7592 DCR Management:
//
//	POST   /apps/register         — OneAuth custom registration
//	POST   /apps/dcr              — RFC 7591 Dynamic Client Registration
//	GET    /apps/dcr/{client_id}  — RFC 7592 DCR Management read (issue #168)
//	GET    /apps                  — List all apps
//	GET    /apps/{id}             — Get app metadata
//	DELETE /apps/{id}             — Delete app
//	POST   /apps/{id}/rotate      — Rotate secret/key
//
// Routing precedence note: Go's ServeMux uses longest-prefix matching, so the
// "/apps/dcr/" prefix below wins over the "/apps/" catch-all without further
// fiddling. The exact-match "/apps/dcr" route handles RFC 7591 registration.
func (h *AppRegistrar) Handler() http.Handler {
	dcr := &DCRHandler{
		KeyStore:  h.KeyStore,
		Auth:      h.Auth,
		Registrar: h,
	}
	dcrMgmt := &DCRManagementHandler{Manager: h}

	mux := http.NewServeMux()
	mux.HandleFunc("/apps/register", h.withAuth(h.handleRegister))
	mux.Handle("/apps/dcr", http.HandlerFunc(dcr.ServeHTTP))
	mux.Handle("/apps/dcr/", http.HandlerFunc(dcrMgmt.ServeHTTP))
	mux.HandleFunc("/apps/", h.withAuth(h.handleAppByID))
	mux.HandleFunc("/apps", h.withAuth(h.handleListApps))
	return mux
}

func (h *AppRegistrar) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.Auth != nil {
			if err := h.Auth.Authenticate(r); err != nil {
				if err == ErrAdminUnauthorized {
					h.jsonError(w, "unauthorized", err.Error(), http.StatusUnauthorized)
				} else {
					h.jsonError(w, "forbidden", err.Error(), http.StatusForbidden)
				}
				return
			}
		}
		next(w, r)
	}
}

func (h *AppRegistrar) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "method_not_allowed", "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientDomain string  `json:"client_domain"`
		SigningAlg   string  `json:"signing_alg"`
		PublicKey    string  `json:"public_key"` // PEM-encoded public key (required for RS256/ES256)
		MaxRooms     int     `json:"max_rooms"`
		MaxMsgRate   float64 `json:"max_msg_rate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid_request", "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.SigningAlg == "" {
		req.SigningAlg = "HS256"
	}

	// Generate client ID
	clientID, err := generateClientID()
	if err != nil {
		h.jsonError(w, "server_error", "Failed to generate client ID", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"client_id":     clientID,
		"client_domain": req.ClientDomain,
		"signing_alg":   req.SigningAlg,
		"max_rooms":     req.MaxRooms,
		"max_msg_rate":  req.MaxMsgRate,
	}

	if utils.IsAsymmetricAlg(req.SigningAlg) {
		// Asymmetric: require public_key PEM, no secret generated
		if req.PublicKey == "" {
			h.jsonError(w, "invalid_request", "public_key is required for "+req.SigningAlg, http.StatusBadRequest)
			return
		}
		// Validate PEM parses to a valid public key of the right type
		if _, err := utils.DecodeVerifyKey([]byte(req.PublicKey), req.SigningAlg); err != nil {
			h.jsonError(w, "invalid_request", "Invalid public key: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Store PEM bytes
		if err := h.KeyStore.PutKey(&keys.KeyRecord{ClientID: clientID, Key: []byte(req.PublicKey), Algorithm: req.SigningAlg}); err != nil {
			h.jsonError(w, "server_error", "Failed to store key", http.StatusInternalServerError)
			return
		}
		// No client_secret in response for asymmetric
	} else {
		// Symmetric: generate secret
		secret, err := generateSecret()
		if err != nil {
			h.jsonError(w, "server_error", "Failed to generate secret", http.StatusInternalServerError)
			return
		}
		if err := h.KeyStore.PutKey(&keys.KeyRecord{ClientID: clientID, Key: []byte(secret), Algorithm: req.SigningAlg}); err != nil {
			h.jsonError(w, "server_error", "Failed to store key", http.StatusInternalServerError)
			return
		}
		resp["client_secret"] = secret
	}

	// Store registration metadata (persists to Store + updates cache).
	reg := &AppRegistration{
		ClientID:     clientID,
		ClientDomain: req.ClientDomain,
		SigningAlg:   req.SigningAlg,
		MaxRooms:     req.MaxRooms,
		MaxMsgRate:   req.MaxMsgRate,
		CreatedAt:    time.Now(),
	}
	if err := h.SaveRegistration(reg); err != nil {
		h.jsonError(w, "server_error", "Failed to persist registration", http.StatusInternalServerError)
		return
	}

	resp["created_at"] = reg.CreatedAt

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (h *AppRegistrar) handleListApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.jsonError(w, "method_not_allowed", "GET required", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	
	apps := make([]*AppRegistration, 0, len(h.apps))
	for _, reg := range h.apps {
		apps = append(apps, reg)
	}
	h.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"apps": apps})
}

func (h *AppRegistrar) handleAppByID(w http.ResponseWriter, r *http.Request) {
	// Parse client_id from path: /apps/{client_id} or /apps/{client_id}/rotate
	path := strings.TrimPrefix(r.URL.Path, "/apps/")
	parts := strings.SplitN(path, "/", 2)
	clientID := parts[0]

	if clientID == "" {
		h.jsonError(w, "invalid_request", "Missing client_id", http.StatusBadRequest)
		return
	}

	// Check for /rotate suffix
	if len(parts) == 2 && parts[1] == "rotate" {
		h.handleRotateSecret(w, r, clientID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetApp(w, r, clientID)
	case http.MethodDelete:
		h.handleDeleteApp(w, r, clientID)
	default:
		h.jsonError(w, "method_not_allowed", "GET or DELETE required", http.StatusMethodNotAllowed)
	}
}

func (h *AppRegistrar) handleGetApp(w http.ResponseWriter, _ *http.Request, clientID string) {
	h.mu.RLock()
	reg, ok := h.apps[clientID]
	h.mu.RUnlock()

	if !ok {
		h.jsonError(w, "not_found", "App not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reg)
}

func (h *AppRegistrar) handleDeleteApp(w http.ResponseWriter, _ *http.Request, clientID string) {
	h.mu.RLock()
	_, ok := h.apps[clientID]
	h.mu.RUnlock()
	if !ok {
		h.jsonError(w, "not_found", "App not found", http.StatusNotFound)
		return
	}

	// Persist deletion first; if the store fails we must not invalidate the
	// in-memory cache or the KeyStore — that would leave the app un-revokable
	// on subsequent restarts (the registration would still hydrate from the
	// store, but the key would be gone).
	if err := h.Store.DeleteApp(clientID); err != nil && err != ErrAppNotFound {
		h.jsonError(w, "server_error", "Failed to delete registration", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	delete(h.apps, clientID)
	h.mu.Unlock()

	// Remove from KeyStore
	h.KeyStore.DeleteKey(clientID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted": true, "client_id": clientID})
}

func (h *AppRegistrar) handleRotateSecret(w http.ResponseWriter, r *http.Request, clientID string) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "method_not_allowed", "POST required", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	reg, ok := h.apps[clientID]
	h.mu.RUnlock()

	if !ok {
		h.jsonError(w, "not_found", "App not found", http.StatusNotFound)
		return
	}

	// Parse optional grace period from request body
	var reqBody struct {
		PublicKey    string `json:"public_key"`
		GracePeriod string `json:"grace_period"` // e.g. "24h", "1h30m"
	}
	// We need to read the body for both symmetric and asymmetric
	json.NewDecoder(r.Body).Decode(&reqBody)

	gracePeriod := h.DefaultGracePeriod
	if gracePeriod == 0 {
		gracePeriod = 24 * time.Hour
	}
	if reqBody.GracePeriod != "" {
		if parsed, err := time.ParseDuration(reqBody.GracePeriod); err == nil {
			gracePeriod = parsed
		}
	}

	// Snapshot old key material before overwrite (for grace period retention)
	var oldKey any
	var oldAlg string
	var oldKid string
	if h.KidStore != nil {
		if oldRec, err := h.KeyStore.GetKey(clientID); err == nil {
			oldKey = oldRec.Key
			oldAlg = oldRec.Algorithm
			oldKid = oldRec.Kid
			if oldKid == "" && oldKey != nil {
				oldKid, _ = utils.ComputeKid(oldKey, oldAlg)
			}
		}
	}

	resp := map[string]any{"client_id": clientID}

	if utils.IsAsymmetricAlg(reg.SigningAlg) {
		// Asymmetric: require new public_key in request body
		if reqBody.PublicKey == "" {
			h.jsonError(w, "invalid_request", "public_key is required for key rotation with "+reg.SigningAlg, http.StatusBadRequest)
			return
		}
		if _, err := utils.DecodeVerifyKey([]byte(reqBody.PublicKey), reg.SigningAlg); err != nil {
			h.jsonError(w, "invalid_request", "Invalid public key: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.KeyStore.PutKey(&keys.KeyRecord{ClientID: clientID, Key: []byte(reqBody.PublicKey), Algorithm: reg.SigningAlg}); err != nil {
			h.jsonError(w, "server_error", "Failed to update key", http.StatusInternalServerError)
			return
		}
	} else {
		// Symmetric: generate new secret
		newSecret, err := generateSecret()
		if err != nil {
			h.jsonError(w, "server_error", "Failed to generate secret", http.StatusInternalServerError)
			return
		}
		if err := h.KeyStore.PutKey(&keys.KeyRecord{ClientID: clientID, Key: []byte(newSecret), Algorithm: reg.SigningAlg}); err != nil {
			h.jsonError(w, "server_error", "Failed to update key", http.StatusInternalServerError)
			return
		}
		resp["client_secret"] = newSecret
	}

	// Retain old key in KidStore for grace period
	if h.KidStore != nil && oldKey != nil && oldKid != "" {
		h.KidStore.Add(oldKid, oldKey, oldAlg, clientID, time.Now().Add(gracePeriod))
		resp["previous_kid"] = oldKid
		resp["grace_period"] = gracePeriod.String()
	}

	// Include new kid in response
	if newRec, err := h.KeyStore.GetKey(clientID); err == nil && newRec.Kid != "" {
		resp["kid"] = newRec.Kid
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *AppRegistrar) jsonError(w http.ResponseWriter, code, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

// generateClientID creates a random client ID like "app_a1b2c3d4e5f6"
func generateClientID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate client ID: %w", err)
	}
	return "app_" + hex.EncodeToString(b), nil
}

// generateSecret creates a random 32-byte hex-encoded secret
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}
