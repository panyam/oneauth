package apiauth

import (
	"encoding/json"
	"net/http"

	"github.com/panyam/oneauth/keys"
)

// RevocationHandler implements OAuth 2.0 Token Revocation (RFC 7009).
// It is a thin HTTP wrapper over TokenRevoker (core logic) and
// ClientAuthenticator (caller verification).
//
// See: https://www.rfc-editor.org/rfc/rfc7009
type RevocationHandler struct {
	// Revoker performs the actual token revocation (transport-independent).
	Revoker TokenRevoker

	// Authenticator verifies the caller's client credentials.
	Authenticator ClientAuthenticator
}

// NewRevocationHandler creates a RevocationHandler from an APIAuth and
// a client KeyLookup. Bridge constructor for existing code.
func NewRevocationHandler(auth *APIAuth, clientKeyStore keys.KeyLookup) *RevocationHandler {
	revoker := NewTokenRevoker(TokenRevokerConfig{
		Blacklist:    auth.Blacklist,
		RefreshStore: auth.RefreshTokenStore,
	})
	return &RevocationHandler{
		Revoker:       revoker,
		Authenticator: NewClientAuthenticator(clientKeyStore),
	}
}

// ServeHTTP handles POST /oauth/revoke per RFC 7009.
func (h *RevocationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form body
	if err := r.ParseForm(); err != nil {
		h.okResponse(w)
		return
	}

	// Authenticate the caller — try Basic auth first, then form params
	clientID, clientSecret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="revocation"`)
		h.errorResponse(w, "invalid_client", "Authentication required", http.StatusUnauthorized)
		return
	}
	if err := h.Authenticator.AuthenticateClient(clientID, clientSecret); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="revocation"`)
		h.errorResponse(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Extract token and hint
	token := r.FormValue("token")
	if token == "" {
		h.okResponse(w)
		return
	}
	hint := r.FormValue("token_type_hint")

	// Delegate to transport-independent revoker
	h.Revoker.Revoke(token, hint)

	// RFC 7009 §2.2: always 200 OK
	h.okResponse(w)
}

// okResponse sends 200 OK with no body (RFC 7009 §2.2).
func (h *RevocationHandler) okResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
}

// errorResponse sends a JSON error (only for auth failures).
func (h *RevocationHandler) errorResponse(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
