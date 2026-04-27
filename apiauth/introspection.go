package apiauth

import (
	"encoding/json"
	"net/http"

	"github.com/panyam/oneauth/keys"
)

// IntrospectionHandler implements OAuth 2.0 Token Introspection (RFC 7662).
// Resource servers POST tokens to this endpoint to check validity, as an
// alternative to local JWT validation via JWKS.
//
// The handler is a thin HTTP wrapper over TokenIntrospector (core logic)
// and ClientAuthenticator (caller verification).
//
// See: https://www.rfc-editor.org/rfc/rfc7662
type IntrospectionHandler struct {
	// Introspector performs the actual token introspection (transport-independent).
	Introspector TokenIntrospector

	// Authenticator verifies the caller's client credentials.
	Authenticator ClientAuthenticator
}

// NewIntrospectionHandler creates an IntrospectionHandler from an APIAuth
// and a client KeyLookup. This is the bridge between the old-style APIAuth
// configuration and the new core interfaces.
func NewIntrospectionHandler(auth *APIAuth, clientKeyStore keys.KeyLookup) *IntrospectionHandler {
	// Build a validator that mirrors APIAuth's validation logic.
	// APIAuth supports both single-key (JWTSecretKey) and multi-tenant (ClientKeyStore).
	// We wrap this by using APIAuth.ValidateAccessTokenFull as the validation backend.
	introspector := &apiauthIntrospector{auth: auth}
	return &IntrospectionHandler{
		Introspector:  introspector,
		Authenticator: NewClientAuthenticator(clientKeyStore),
	}
}

// apiauthIntrospector adapts an APIAuth into a TokenIntrospector.
// This preserves the exact validation behavior of the old IntrospectionHandler.
type apiauthIntrospector struct {
	auth *APIAuth
}

func (ai *apiauthIntrospector) Introspect(tokenString string) (*IntrospectionResult, error) {
	userID, scopes, _, err := ai.auth.ValidateAccessTokenFull(tokenString)
	if err != nil {
		return &IntrospectionResult{Active: false}, nil
	}

	rawClaims := parseRawJWTClaims(tokenString)

	result := &IntrospectionResult{
		Active:    true,
		Sub:       userID,
		TokenType: "access_token",
	}

	if len(scopes) > 0 {
		result.Scope = joinScopes(scopes)
	}

	if rawClaims != nil {
		if v, ok := rawClaims["iss"].(string); ok {
			result.Iss = v
		}
		if v, ok := rawClaims["exp"].(float64); ok {
			result.Exp = int64(v)
		}
		if v, ok := rawClaims["iat"].(float64); ok {
			result.Iat = int64(v)
		}
		if v, ok := rawClaims["jti"].(string); ok {
			result.Jti = v
		}
		if v, ok := rawClaims["aud"]; ok {
			result.Aud = v
		}
		if v, ok := rawClaims["client_id"].(string); ok {
			result.ClientID = v
		}
	}

	return result, nil
}

func joinScopes(scopes []string) string {
	s := ""
	for i, sc := range scopes {
		if i > 0 {
			s += " "
		}
		s += sc
	}
	return s
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
	if err := h.Authenticator.AuthenticateClient(clientID, clientSecret); err != nil {
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

	// Delegate to transport-independent introspector
	result, err := h.Introspector.Introspect(token)
	if err != nil || !result.Active {
		// RFC 7662: invalid tokens get {"active": false}, never an error
		h.jsonResponse(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	// Build response from IntrospectionResult
	resp := map[string]any{
		"active":     true,
		"sub":        result.Sub,
		"token_type": result.TokenType,
	}
	if result.Scope != "" {
		resp["scope"] = result.Scope
	}
	if result.Iss != "" {
		resp["iss"] = result.Iss
	}
	if result.Exp != 0 {
		resp["exp"] = result.Exp
	}
	if result.Iat != 0 {
		resp["iat"] = result.Iat
	}
	if result.Aud != nil {
		resp["aud"] = result.Aud
	}
	if result.Jti != "" {
		resp["jti"] = result.Jti
	}
	if result.ClientID != "" {
		resp["client_id"] = result.ClientID
	}

	// Include authorization_details if present (RFC 9396 §9.1)
	rawClaims := parseRawJWTClaims(token)
	if ad, ok := rawClaims["authorization_details"]; ok {
		resp["authorization_details"] = ad
	}

	h.jsonResponse(w, http.StatusOK, resp)
}

// jsonResponse writes a JSON response with the given status code.
func (h *IntrospectionHandler) jsonResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
