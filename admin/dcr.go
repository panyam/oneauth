package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

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
// On successful registration the response includes a registration access
// token + management URI (RFC 7592 §3) which the client uses to read,
// update, or delete its own registration via /apps/dcr/{client_id}.
//
// See: https://www.rfc-editor.org/rfc/rfc7591
// See: https://www.rfc-editor.org/rfc/rfc7592
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

	// IssuerBaseURL is the public base URL used to construct
	// registration_client_uri values returned in DCR responses
	// (e.g. "https://auth.example.com"). When empty, the URI is
	// built from the incoming request's scheme + Host header — fine
	// for tests but unreliable behind proxies, so production
	// deployments should set this explicitly.
	IssuerBaseURL string
}

// DCRRequest is the RFC 7591 client registration request, also reused as the
// RFC 7592 §2.2 update request body.
//
// On RFC 7591 registration the ClientID field is unused — the server assigns
// the value. On RFC 7592 PUT the client MUST include its existing client_id;
// the HTTP wrapper validates that it matches the URL path before invoking
// ClientRegistrationManager.UpdateRegistration.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2
// See: https://www.rfc-editor.org/rfc/rfc7592#section-2.2
type DCRRequest struct {
	// ClientID is required for PUT (RFC 7592 §2.2), ignored for register.
	ClientID string `json:"client_id,omitempty"`

	// Client metadata
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`

	// Authentication method
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// RFC 9396 — authorization details types this client intends to use
	AuthorizationDetailsTypes []string `json:"authorization_details_types,omitempty"`

	// Keys — for asymmetric auth methods (private_key_jwt)
	JWKS *utils.JWKSet `json:"jwks,omitempty"`
}

// DCRResponse is the RFC 7591 client registration response, extended with the
// RFC 7592 §3 management credentials (registration_access_token +
// registration_client_uri) so that registered clients can subsequently call
// /apps/dcr/{client_id} to read, update, or delete their own registration.
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1
// See: https://www.rfc-editor.org/rfc/rfc7592#section-3
type DCRResponse struct {
	ClientID                  string   `json:"client_id"`
	ClientSecret              string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt          int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt     int64    `json:"client_secret_expires_at"`
	ClientName                string   `json:"client_name,omitempty"`
	ClientURI                 string   `json:"client_uri,omitempty"`
	RedirectURIs              []string `json:"redirect_uris,omitempty"`
	GrantTypes                []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod   string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                     string   `json:"scope,omitempty"`
	AuthorizationDetailsTypes []string `json:"authorization_details_types,omitempty"` // RFC 9396

	// RFC 7592 §3 — management credentials.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// ServeHTTP is the HTTP wrapper for ClientRegistrar.Register (RFC 7591 DCR).
// All protocol logic lives behind the interface; this method just parses,
// authenticates, calls the manager, and formats the response. See #172 for
// the convention this follows (the same shape used by ClientRegistrationManager
// in #168 / #169 / #170).
func (h *DCRHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Auth != nil {
		if err := h.Auth.Authenticate(r); err != nil {
			h.jsonError(w, "invalid_token", "Authentication required", http.StatusUnauthorized)
			return
		}
	}

	var body DCRRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.jsonError(w, "invalid_client_metadata", "Invalid JSON body", http.StatusBadRequest)
		return
	}
	// IssuerBaseURL falls back to the inbound request's scheme + host when
	// no explicit value is configured on the handler — matches pre-refactor
	// behavior (see DCRHandler.buildRegistrationClientURI).
	issuerBase := h.IssuerBaseURL
	if issuerBase == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		issuerBase = scheme + "://" + r.Host
	}

	if h.Registrar == nil {
		// Defensive — Handler() always wires a registrar. A nil here would
		// be a programming error and the manager has no place to store
		// registration metadata.
		h.jsonError(w, "server_error", "Registrar not configured", http.StatusInternalServerError)
		return
	}
	resp, err := h.Registrar.Register(r.Context(), &RegisterRequest{
		Metadata:      &body,
		IssuerBaseURL: issuerBase,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidClientMetadata) {
			h.jsonError(w, "invalid_client_metadata", err.Error(), http.StatusBadRequest)
			return
		}
		h.jsonError(w, "server_error", err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp.Registration)
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

// generateRegistrationAccessToken returns a 32-byte (256-bit) hex-encoded random
// token used as the RFC 7592 management credential for a DCR-registered client.
// The token is stored on AppRegistration.RegistrationAccessToken and validated
// on every /apps/dcr/{client_id} request via DCRManagementHandler.
func generateRegistrationAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate registration access token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

