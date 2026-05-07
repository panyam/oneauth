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
// Issue #168 ships GET; #169 / #170 add PUT / DELETE. Until those land
// non-GET methods return 405 with an Allow header.
//
// See: https://www.rfc-editor.org/rfc/rfc7592
type DCRManagementHandler struct {
	// Manager is the transport-agnostic core. Required.
	Manager ClientRegistrationManager
}

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
	default:
		// 405 does not depend on client_id or auth, so it leaks no per-client
		// information. The Allow header advertises what's currently supported.
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *DCRManagementHandler) handleGet(w http.ResponseWriter, r *http.Request, clientID string) {
	token := bearerToken(r.Header.Get("Authorization"))
	resp, err := h.Manager.GetRegistration(clientID, token)
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
	_ = json.NewEncoder(w).Encode(resp)
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
