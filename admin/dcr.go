package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// DCRHandler implements OAuth 2.0 Dynamic Client Registration (RFC 7591)
// as a conformance wrapper around AppRegistrar. It accepts standard DCR
// request format and maps to/from the internal AppRegistrar model.
//
// Automatically mounted by AppRegistrar.Handler() at POST /apps/dcr.
// Existing /apps/* endpoints continue working unchanged.
//
// See: https://www.rfc-editor.org/rfc/rfc7591
type DCRHandler struct {
	// KeyStore stores client credentials (same KeyStore as AppRegistrar).
	KeyStore keys.KeyStorage

	// Auth authenticates the caller. Supports both:
	//   - Initial access token via Authorization: Bearer header (RFC 7591 §3)
	//   - X-Admin-Key header (OneAuth custom, backward-compatible)
	// If nil, registration is open (not recommended for production).
	Auth AdminAuth

	// Registrar is the underlying AppRegistrar for metadata storage.
	// If nil, client metadata is not persisted (only KeyStore is used).
	Registrar *AppRegistrar
}

// DCRRequest is the RFC 7591 client registration request.
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
type DCRRequest struct {
	// Client metadata
	ClientName  string   `json:"client_name,omitempty"`
	ClientURI   string   `json:"client_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	GrantTypes  []string `json:"grant_types,omitempty"`
	Scope       string   `json:"scope,omitempty"`

	// Authentication method
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// Keys — for asymmetric auth methods (private_key_jwt)
	JWKS *utils.JWKSet `json:"jwks,omitempty"`
}

// DCRResponse is the RFC 7591 client registration response.
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1
type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// ServeHTTP handles POST /register per RFC 7591.
func (h *DCRHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate caller — try Bearer token first, then X-Admin-Key
	if h.Auth != nil {
		if err := h.Auth.Authenticate(r); err != nil {
			h.jsonError(w, "invalid_token", "Authentication required", http.StatusUnauthorized)
			return
		}
	}

	// Parse DCR request
	var req DCRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid_client_metadata", "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Determine signing algorithm from auth method
	signingAlg := "HS256" // default
	if req.TokenEndpointAuthMethod == "private_key_jwt" {
		// Asymmetric — need JWKS
		if req.JWKS == nil || len(req.JWKS.Keys) == 0 {
			h.jsonError(w, "invalid_client_metadata", "jwks required for private_key_jwt", http.StatusBadRequest)
			return
		}
		// Use the first key's algorithm
		signingAlg = req.JWKS.Keys[0].Alg
		if signingAlg == "" {
			signingAlg = "RS256" // default asymmetric
		}
	}

	// Generate client ID
	clientID, err := generateDCRClientID()
	if err != nil {
		h.jsonError(w, "server_error", "Failed to generate client_id", http.StatusInternalServerError)
		return
	}

	resp := DCRResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0, // never expires
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
	}

	if utils.IsAsymmetricAlg(signingAlg) {
		// Convert JWK to PEM and store
		jwk := req.JWKS.Keys[0]
		pubKey, _, err := utils.JWKToPublicKey(jwk)
		if err != nil {
			h.jsonError(w, "invalid_client_metadata", "Invalid JWK: "+err.Error(), http.StatusBadRequest)
			return
		}
		pemBytes, err := utils.EncodePublicKeyPEM(pubKey)
		if err != nil {
			h.jsonError(w, "server_error", "Failed to encode public key", http.StatusInternalServerError)
			return
		}
		if err := h.KeyStore.PutKey(&keys.KeyRecord{ClientID: clientID, Key: pemBytes, Algorithm: signingAlg}); err != nil {
			h.jsonError(w, "server_error", "Failed to store key", http.StatusInternalServerError)
			return
		}
	} else {
		// Symmetric — generate secret
		secret, err := generateDCRSecret()
		if err != nil {
			h.jsonError(w, "server_error", "Failed to generate secret", http.StatusInternalServerError)
			return
		}
		if err := h.KeyStore.PutKey(&keys.KeyRecord{ClientID: clientID, Key: []byte(secret), Algorithm: signingAlg}); err != nil {
			h.jsonError(w, "server_error", "Failed to store key", http.StatusInternalServerError)
			return
		}
		resp.ClientSecret = secret
		if resp.TokenEndpointAuthMethod == "" {
			resp.TokenEndpointAuthMethod = "client_secret_post"
		}
	}

	// Store metadata in AppRegistrar if available
	if h.Registrar != nil {
		domain := req.ClientURI
		if domain == "" {
			domain = req.ClientName
		}
		reg := &AppRegistration{
			ClientID:     clientID,
			ClientDomain: domain,
			SigningAlg:   signingAlg,
			CreatedAt:    time.Now(),
		}
		h.Registrar.mu.Lock()
		h.Registrar.apps[clientID] = reg
		h.Registrar.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (h *DCRHandler) jsonError(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

func generateDCRClientID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate client ID: %w", err)
	}
	return "app_" + hex.EncodeToString(b), nil
}

func generateDCRSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}
