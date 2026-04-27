package apiauth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

// RevocationHandler implements OAuth 2.0 Token Revocation (RFC 7009).
// Clients POST a token to this endpoint to notify the AS that the token
// is no longer needed. The AS revokes it so that subsequent introspection
// or validation attempts fail.
//
// The handler:
//   - Accepts POST with application/x-www-form-urlencoded body (token=...&token_type_hint=...)
//   - Authenticates the caller via ClientKeyStore (Basic auth or client_secret_post)
//   - Revokes access tokens via the Blacklist (jti-based)
//   - Revokes refresh tokens via the RefreshTokenStore
//   - Always returns 200 OK — never reveals whether the token existed (RFC 7009 §2.2)
//
// See: https://www.rfc-editor.org/rfc/rfc7009
type RevocationHandler struct {
	// Auth is the APIAuth instance used to parse and validate access tokens.
	Auth *APIAuth

	// ClientKeyStore authenticates callers of the revocation endpoint.
	// Clients must present valid client_id + client_secret via HTTP Basic auth
	// or as form parameters (client_secret_post). If nil, all callers are rejected.
	ClientKeyStore keys.KeyLookup
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
		h.okResponse(w) // don't leak parse errors
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
	if err := h.authenticateCaller(clientID, clientSecret); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="revocation"`)
		h.errorResponse(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Extract token and hint
	token := r.FormValue("token")
	if token == "" {
		// RFC 7009 §2.1: "token" is required, but we still return 200
		h.okResponse(w)
		return
	}
	hint := r.FormValue("token_type_hint")

	// Revoke based on hint (or try both if no hint)
	switch hint {
	case "refresh_token":
		h.revokeRefreshToken(token)
	case "access_token":
		h.revokeAccessToken(token)
	default:
		// No hint — try refresh token first (cheaper), then access token
		if !h.revokeRefreshToken(token) {
			h.revokeAccessToken(token)
		}
	}

	// RFC 7009 §2.2: "The authorization server responds with HTTP status
	// code 200 for both the case where the token was successfully revoked
	// and the case where the client submitted an invalid token."
	h.okResponse(w)
}

// revokeRefreshToken attempts to revoke a refresh token. Returns true if the
// token was found in the refresh token store (whether revoked now or already revoked).
func (h *RevocationHandler) revokeRefreshToken(token string) bool {
	if h.Auth == nil || h.Auth.RefreshTokenStore == nil {
		return false
	}
	// Check if this token exists as a refresh token first
	rt, err := h.Auth.RefreshTokenStore.GetRefreshToken(token)
	if err != nil || rt == nil {
		return false // not a refresh token
	}
	// Found it — revoke if not already revoked
	if !rt.Revoked {
		h.Auth.RefreshTokenStore.RevokeRefreshToken(token)
	}
	return true
}

// revokeAccessToken attempts to revoke a JWT access token by extracting its
// jti claim and adding it to the blacklist.
func (h *RevocationHandler) revokeAccessToken(token string) {
	if h.Auth == nil || h.Auth.Blacklist == nil {
		return
	}

	// Parse JWT without full validation — we just need jti and exp.
	// The token might be expired already (that's fine, we still blacklist it
	// to handle clock skew).
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return // not a JWT — silently ignore per RFC 7009
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return
	}

	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return // no jti — can't blacklist
	}

	// Extract expiry for blacklist TTL
	expiry := time.Now().Add(core.TokenExpiryAccessToken) // default
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		expiry = exp.Time
	}

	h.Auth.Blacklist.Revoke(jti, expiry)
}

// authenticateCaller verifies the caller's credentials against the ClientKeyStore.
func (h *RevocationHandler) authenticateCaller(clientID, clientSecret string) error {
	if h.ClientKeyStore == nil {
		return errInvalidClient
	}
	rec, err := h.ClientKeyStore.GetKey(clientID)
	if err != nil || rec == nil {
		return errInvalidClient
	}
	storedKey, ok := rec.Key.([]byte)
	if !ok {
		return errInvalidClient
	}
	if !constantTimeEqual(string(storedKey), clientSecret) {
		return errInvalidClient
	}
	return nil
}

// okResponse sends 200 OK with no body (RFC 7009 §2.2).
func (h *RevocationHandler) okResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
}

// errorResponse sends a JSON error (only for auth failures — token errors always get 200).
func (h *RevocationHandler) errorResponse(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
