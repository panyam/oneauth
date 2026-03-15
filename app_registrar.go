package oneauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
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
type AppRegistrar struct {
	KeyStore WritableKeyStore
	Auth     AdminAuth

	mu   sync.RWMutex
	apps map[string]*AppRegistration
}

func (h *AppRegistrar) init() {
	if h.apps == nil {
		h.apps = make(map[string]*AppRegistration)
	}
}

// RLockApps calls fn with a read-locked view of all registered apps.
func (h *AppRegistrar) RLockApps(fn func(map[string]*AppRegistration)) {
	h.mu.RLock()
	h.init()
	fn(h.apps)
	h.mu.RUnlock()
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

	// Generate client ID and secret
	clientID, err := generateClientID()
	if err != nil {
		h.jsonError(w, "server_error", "Failed to generate client ID", http.StatusInternalServerError)
		return
	}
	secret, err := generateSecret()
	if err != nil {
		h.jsonError(w, "server_error", "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	// Store in KeyStore
	if err := h.KeyStore.RegisterKey(clientID, []byte(secret), req.SigningAlg); err != nil {
		h.jsonError(w, "server_error", "Failed to store key", http.StatusInternalServerError)
		return
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
	h.init()
	h.apps[clientID] = reg
	h.mu.Unlock()

	// Return client_id and secret (secret is only shown once)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"client_id":     clientID,
		"client_secret": secret,
		"client_domain": reg.ClientDomain,
		"signing_alg":   reg.SigningAlg,
		"max_rooms":     reg.MaxRooms,
		"max_msg_rate":  reg.MaxMsgRate,
		"created_at":    reg.CreatedAt,
	})
}

func (h *AppRegistrar) handleListApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.jsonError(w, "method_not_allowed", "GET required", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	h.init()
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
	h.init()
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
	h.init()
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
	h.init()
	reg, ok := h.apps[clientID]
	h.mu.RUnlock()

	if !ok {
		h.jsonError(w, "not_found", "App not found", http.StatusNotFound)
		return
	}

	newSecret, err := generateSecret()
	if err != nil {
		h.jsonError(w, "server_error", "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	if err := h.KeyStore.RegisterKey(clientID, []byte(newSecret), reg.SigningAlg); err != nil {
		h.jsonError(w, "server_error", "Failed to update key", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"client_id":     clientID,
		"client_secret": newSecret,
	})
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
