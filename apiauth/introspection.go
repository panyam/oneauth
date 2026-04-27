package apiauth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/keys"
)

// IntrospectionHandler implements OAuth 2.0 Token Introspection (RFC 7662).
// Resource servers POST tokens to this endpoint to check validity, as an
// alternative to local JWT validation via JWKS.
//
// The handler:
//   - Accepts POST with application/x-www-form-urlencoded body (token=...)
//   - Authenticates the caller via ClientKeyStore (Basic auth)
//   - Validates the token using APIAuth.ValidateAccessTokenFull
//   - Checks the token blacklist if configured on APIAuth
//   - Returns {"active": true, ...claims} for valid tokens
//   - Returns {"active": false} for ANY invalid token (never reveals why)
//
// See: https://www.rfc-editor.org/rfc/rfc7662
type IntrospectionHandler struct {
	// Auth is the APIAuth instance used to validate tokens.
	// Must have JWTSecretKey (or JWTVerifyKey) configured.
	Auth *APIAuth

	// ClientKeyStore authenticates callers of the introspection endpoint.
	// Resource servers must present valid client_id + client_secret via
	// HTTP Basic auth. If nil, all callers are rejected.
	ClientKeyStore keys.KeyLookup
}

// ServeHTTP handles POST /oauth/introspect per RFC 7662.
func (h *IntrospectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate the caller (resource server) via Basic auth
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.authenticateCaller(clientID, clientSecret); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse form body
	if err := r.ParseForm(); err != nil {
		h.jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	token := r.FormValue("token")
	if token == "" {
		h.jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": "token parameter is required"})
		return
	}

	// Validate the token using APIAuth (checks signature, expiry, blacklist)
	userID, scopes, _, err := h.Auth.ValidateAccessTokenFull(token)
	if err != nil {
		// RFC 7662: invalid tokens get {"active": false}, never an error
		h.jsonResponse(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	// Parse raw claims for the introspection response (ValidateAccessTokenFull
	// strips standard claims from customClaims, but we need them here)
	rawClaims := h.parseRawClaims(token)

	// Build the introspection response
	resp := map[string]any{
		"active":     true,
		"sub":        userID,
		"token_type": "access_token",
	}

	// Add scope as space-separated string (RFC 7662 §2.2)
	if len(scopes) > 0 {
		resp["scope"] = strings.Join(scopes, " ")
	}

	// Add standard claims from the raw token
	for _, claim := range []string{"iss", "exp", "iat", "aud", "jti", "client_id"} {
		if v, ok := rawClaims[claim]; ok {
			resp[claim] = v
		}
	}

	// Include authorization_details if present (RFC 9396 §9.1)
	if ad, ok := rawClaims["authorization_details"]; ok {
		resp["authorization_details"] = ad
	}

	h.jsonResponse(w, http.StatusOK, resp)
}

// parseRawClaims extracts all claims from a JWT without validation.
// Used to populate the introspection response with standard claims that
// ValidateAccessTokenFull strips from customClaims.
func (h *IntrospectionHandler) parseRawClaims(tokenStr string) map[string]any {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	return claims
}

// authenticateCaller verifies the caller's client_id + client_secret against
// the ClientKeyStore using constant-time comparison.
func (h *IntrospectionHandler) authenticateCaller(clientID, clientSecret string) error {
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

var errInvalidClient = &clientError{"invalid_client"}

type clientError struct{ msg string }

func (e *clientError) Error() string { return e.msg }

// jsonResponse writes a JSON response with the given status code.
func (h *IntrospectionHandler) jsonResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
