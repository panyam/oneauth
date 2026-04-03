package admin

import (
	"crypto/rand"
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
type AppRegistration struct {
	ClientID     string    `json:"client_id"`
	ClientDomain string    `json:"client_domain"`
	SigningAlg   string    `json:"signing_alg"`
	MaxRooms     int       `json:"max_rooms,omitempty"`
	MaxMsgRate   float64   `json:"max_msg_rate,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Revoked      bool      `json:"revoked"`
}

// AppRegistrar is an embeddable HTTP handler for App registration CRUD.
// Mount it on any admin service's mux to let apps register and obtain signing credentials.
// Create with NewAppRegistrar().
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

	mu   sync.RWMutex
	apps map[string]*AppRegistration
}

// NewAppRegistrar creates an AppRegistrar with initialized internal state.
func NewAppRegistrar(keyStore keys.KeyStorage, auth AdminAuth) *AppRegistrar {
	return &AppRegistrar{
		KeyStore: keyStore,
		Auth:     auth,
		apps:     make(map[string]*AppRegistration),
	}
}

// RLockApps calls fn with a read-locked view of all registered apps.
func (h *AppRegistrar) RLockApps(fn func(map[string]*AppRegistration)) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	fn(h.apps)
}

// Handler returns an http.Handler for app registration endpoints.
func (h *AppRegistrar) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/apps/register", h.withAuth(h.handleRegister))
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

	// Store registration metadata
	reg := &AppRegistration{
		ClientID:     clientID,
		ClientDomain: req.ClientDomain,
		SigningAlg:   req.SigningAlg,
		MaxRooms:     req.MaxRooms,
		MaxMsgRate:   req.MaxMsgRate,
		CreatedAt:    time.Now(),
	}
	h.mu.Lock()
	h.apps[clientID] = reg
	h.mu.Unlock()

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
	h.mu.Lock()
	_, ok := h.apps[clientID]
	if !ok {
		h.mu.Unlock()
		h.jsonError(w, "not_found", "App not found", http.StatusNotFound)
		return
	}
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
