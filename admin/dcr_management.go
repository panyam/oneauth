package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// DCRManagementHandler is the HTTP transport adapter for the RFC 7592
// management protocol — it parses the request, hands off to a
// ClientRegistrationManager, then formats the response. All protocol /
// authorization decisions live behind the interface so the same logic is
// usable from gRPC, in-process callers, and tests without HTTP machinery.
//
// #168 ships GET; #169 ships PUT; #170 adds DELETE. Until DELETE lands
// it returns 405 with an Allow header advertising the supported methods.
//
// See: https://www.rfc-editor.org/rfc/rfc7592
type DCRManagementHandler struct {
	// Manager is the transport-agnostic core. Required.
	Manager ClientRegistrationManager
}

// allowedMethods is the value of the Allow header on 405 responses. Updated
// when new verbs come online so a single string captures the supported set.
const allowedMethods = "GET, PUT"

// ServeHTTP routes /apps/dcr/{client_id} requests by HTTP method.
func (h *DCRManagementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientID := extractClientID(r.URL.Path)
	if clientID == "" {
		dcrUnauthorized(w, "invalid_token", "Missing client identifier")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r, clientID)
	case http.MethodPut:
		h.handlePut(w, r, clientID)
	default:
		// 405 does not depend on client_id or auth, so it leaks no per-client
		// information. The Allow header advertises what's currently supported.
		w.Header().Set("Allow", allowedMethods)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *DCRManagementHandler) handlePut(w http.ResponseWriter, r *http.Request, clientID string) {
	token := bearerToken(r.Header.Get("Authorization"))

	// Limit body size to prevent unbounded JSON payloads from exhausting memory.
	// 64 KiB is generous for client metadata; tighten if it ever feels too loose.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	var body DCRRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		dcrBadRequest(w, "invalid_client_metadata", "Invalid JSON body")
		return
	}

	// RFC 7592 §2.2: the client MUST include the client_id and it MUST match
	// the registered identifier. We enforce here so the manager only sees
	// validated requests.
	if body.ClientID == "" || body.ClientID != clientID {
		dcrBadRequest(w, "invalid_client_metadata", "client_id in body must match URL path")
		return
	}

	resp, err := h.Manager.UpdateRegistration(r.Context(), &UpdateRegistrationRequest{
		ClientID:    clientID,
		AccessToken: token,
		Metadata:    &body,
	})
	switch {
	case errors.Is(err, ErrUnauthorized):
		dcrUnauthorized(w, "invalid_token", "Invalid registration access token")
		return
	case errors.Is(err, ErrInvalidClientMetadata):
		dcrBadRequest(w, "invalid_client_metadata", "Update rejected: "+err.Error())
		return
	case err != nil:
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp.Registration)
}

func (h *DCRManagementHandler) handleGet(w http.ResponseWriter, r *http.Request, clientID string) {
	token := bearerToken(r.Header.Get("Authorization"))
	resp, err := h.Manager.GetRegistration(r.Context(), &GetRegistrationRequest{
		ClientID:    clientID,
		AccessToken: token,
	})
	if errors.Is(err, ErrUnauthorized) {
		dcrUnauthorized(w, "invalid_token", "Invalid registration access token")
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp.Registration)
}

// extractClientID parses the trailing segment of /apps/dcr/{client_id}.
// Returns "" if the path doesn't match. Trailing slashes are tolerated;
// nested paths (which #169 / #170 might add for sub-resources) are not.
func extractClientID(path string) string {
	const prefix = "/apps/dcr/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header. Returns "" when the header is missing, malformed, or uses a
// different scheme (Basic, etc.).
func bearerToken(header string) string {
	const scheme = "Bearer "
	if len(header) < len(scheme) {
		return ""
	}
	if !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

// dcrUnauthorized writes an RFC 6750-shaped error response with the standard
// no-store cache headers required for token-bearing endpoints.
func dcrUnauthorized(w http.ResponseWriter, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

// dcrBadRequest writes an RFC 7591/7592 client-metadata error (HTTP 400).
// Used when the request is well-authenticated but the body fails validation
// (malformed JSON, missing/mismatched client_id, locked-field change, etc.).
func dcrBadRequest(w http.ResponseWriter, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
