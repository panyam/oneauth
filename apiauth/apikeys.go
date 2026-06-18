package apiauth

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/panyam/oneauth/core"
)

// APIKeysHandler serves the API-key management endpoints:
//
//	GET    /api/keys      → list the caller's keys (HandleAPIKeys)
//	POST   /api/keys      → create a key       (HandleAPIKeys)
//	DELETE /api/keys/{id} → revoke a key       (HandleRevokeAPIKey)
//
// The caller's identity is read from the request context, populated
// upstream by APIMiddleware. APIKeysHandler does not authenticate the
// request itself.
//
// Moving API-key auth out of apiauth/ entirely is tracked as a
// follow-up — it isn't OAuth. For now it lives here with a focused
// dependency set rather than on the soon-to-be-deleted APIAuth god
// struct.
type APIKeysHandler struct {
	// Store backs the keys. Required.
	Store core.APIKeyStore

	// GetSubjectScopes returns the scope set the caller may grant to
	// keys they create. Nil falls back to a permissive default of
	// {read, write, profile} — suitable for first-light deployments.
	GetSubjectScopes core.GetSubjectScopesFunc
}

// NewAPIKeysHandler constructs an APIKeysHandler.
func NewAPIKeysHandler(store core.APIKeyStore, getSubjectScopes core.GetSubjectScopesFunc) *APIKeysHandler {
	return &APIKeysHandler{Store: store, GetSubjectScopes: getSubjectScopes}
}

// HandleAPIKeys routes GET → list, POST → create.
func (h *APIKeysHandler) HandleAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleList(w, r)
	case http.MethodPost:
		h.handleCreate(w, r)
	default:
		writeAPIErrorJSON(w, "invalid_request", "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleRevokeAPIKey serves DELETE /api/keys/{keyID}. Verifies the
// key belongs to the caller before revoking.
func (h *APIKeysHandler) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeAPIErrorJSON(w, "invalid_request", "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := core.GetSubjectFromContext(r.Context())
	if userID == "" {
		writeAPIErrorJSON(w, "unauthorized", "authentication required", http.StatusUnauthorized)
		return
	}

	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) == 0 {
		writeAPIErrorJSON(w, "invalid_request", "key id required", http.StatusBadRequest)
		return
	}
	keyID := parts[len(parts)-1]
	if keyID == "" || keyID == "keys" {
		writeAPIErrorJSON(w, "invalid_request", "key id required", http.StatusBadRequest)
		return
	}

	getResp, err := h.Store.GetAPIKeyByID(r.Context(), &core.GetAPIKeyByIDRequest{KeyID: keyID})
	if err != nil {
		if err == core.ErrAPIKeyNotFound {
			writeAPIErrorJSON(w, "not_found", "api key not found", http.StatusNotFound)
		} else {
			writeAPIErrorJSON(w, "server_error", "failed to get api key", http.StatusInternalServerError)
		}
		return
	}

	if getResp.APIKey.Subject != userID {
		writeAPIErrorJSON(w, "forbidden", "not authorized to revoke this key", http.StatusForbidden)
		return
	}

	if _, err := h.Store.RevokeAPIKey(r.Context(), &core.RevokeAPIKeyRequest{KeyID: keyID}); err != nil {
		log.Printf("revoke api key: %v", err)
		writeAPIErrorJSON(w, "server_error", "failed to revoke api key", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *APIKeysHandler) handleList(w http.ResponseWriter, r *http.Request) {
	userID := core.GetSubjectFromContext(r.Context())
	if userID == "" {
		writeAPIErrorJSON(w, "unauthorized", "authentication required", http.StatusUnauthorized)
		return
	}

	listResp, err := h.Store.ListSubjectAPIKeys(r.Context(), &core.ListSubjectAPIKeysRequest{Subject: userID})
	if err != nil {
		log.Printf("list api keys: %v", err)
		writeAPIErrorJSON(w, "server_error", "failed to list api keys", http.StatusInternalServerError)
		return
	}

	type apiKeyInfo struct {
		KeyID      string     `json:"key_id"`
		Name       string     `json:"name"`
		Scopes     []string   `json:"scopes,omitempty"`
		CreatedAt  time.Time  `json:"created_at"`
		ExpiresAt  *time.Time `json:"expires_at,omitempty"`
		LastUsedAt time.Time  `json:"last_used_at"`
		Revoked    bool       `json:"revoked"`
	}

	out := make([]apiKeyInfo, 0, len(listResp.APIKeys))
	for _, k := range listResp.APIKeys {
		out = append(out, apiKeyInfo{
			KeyID:      k.KeyID,
			Name:       k.Name,
			Scopes:     k.Scopes,
			CreatedAt:  k.CreatedAt,
			ExpiresAt:  k.ExpiresAt,
			LastUsedAt: k.LastUsedAt,
			Revoked:    k.Revoked,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": out})
}

func (h *APIKeysHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	userID := core.GetSubjectFromContext(r.Context())
	if userID == "" {
		writeAPIErrorJSON(w, "unauthorized", "authentication required", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes,omitempty"`
		ExpiresIn int64    `json:"expires_in,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIErrorJSON(w, "invalid_request", "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		writeAPIErrorJSON(w, "invalid_request", "name is required", http.StatusBadRequest)
		return
	}

	allowedScopes := []string{core.ScopeRead, core.ScopeWrite, core.ScopeProfile}
	if h.GetSubjectScopes != nil {
		s, err := h.GetSubjectScopes(userID)
		if err != nil {
			log.Printf("get subject scopes: %v", err)
			writeAPIErrorJSON(w, "server_error", "failed to get user permissions", http.StatusInternalServerError)
			return
		}
		allowedScopes = s
	}

	grantedScopes := req.Scopes
	if len(grantedScopes) == 0 {
		grantedScopes = allowedScopes
	} else {
		grantedScopes = core.IntersectScopes(req.Scopes, allowedScopes)
	}

	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	createResp, err := h.Store.CreateAPIKey(r.Context(), &core.CreateAPIKeyRequest{
		Subject:   userID,
		Name:      req.Name,
		Scopes:    grantedScopes,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		log.Printf("create api key: %v", err)
		writeAPIErrorJSON(w, "server_error", "failed to create api key", http.StatusInternalServerError)
		return
	}
	apiKey := createResp.APIKey

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"api_key":    createResp.FullKey, // full key is shown only at creation time
		"key_id":     apiKey.KeyID,
		"name":       apiKey.Name,
		"scopes":     apiKey.Scopes,
		"created_at": apiKey.CreatedAt,
		"expires_at": apiKey.ExpiresAt,
	})
}

// writeAPIErrorJSON is the canonical error response used by the API-
// key endpoints. Keeps the error shape consistent with the rest of
// the JSON-bodied API endpoints (matches what the legacy
// APIAuth.errorResponse wrote).
func writeAPIErrorJSON(w http.ResponseWriter, code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(core.TokenError{
		Error:            code,
		ErrorDescription: description,
	})
}
