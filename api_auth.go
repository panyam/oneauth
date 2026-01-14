package oneauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// APIAuth handles API token-based authentication
type APIAuth struct {
	// Stores
	RefreshTokenStore RefreshTokenStore
	APIKeyStore       APIKeyStore

	// JWT configuration
	JWTSecretKey  string // Secret key for signing JWTs
	JWTIssuer     string // Issuer claim (e.g., "myapp")
	JWTAudience   string // Audience claim (e.g., "api")
	JWTSigningAlg string // Signing algorithm (defaults to HS256)

	// Token configuration
	AccessTokenExpiry  time.Duration // Defaults to 15 minutes
	RefreshTokenExpiry time.Duration // Defaults to 7 days

	// Callbacks
	ValidateCredentials CredentialsValidator       // Validates username/password
	GetUserScopes       GetUserScopesFunc          // Returns allowed scopes for a user
	OnLoginSuccess      func(userID string, r *http.Request) // Optional: for logging/analytics
	OnLoginFailure      func(username string, r *http.Request, err error) // Optional: for logging/analytics

	// Rate limiting (optional)
	RateLimiter RateLimiter
}

// RateLimiter interface for rate limiting login attempts
type RateLimiter interface {
	Allow(key string) bool
}

// ServeHTTP handles the /api/login endpoint
func (a *APIAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.errorResponse(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.errorResponse(w, "invalid_request", "Invalid request body", http.StatusBadRequest)
		return
	}

	// Handle based on grant type
	switch req.GrantType {
	case "password":
		a.handlePasswordGrant(w, r, &req)
	case "refresh_token":
		a.handleRefreshTokenGrant(w, r, &req)
	default:
		a.errorResponse(w, "unsupported_grant_type", "Grant type not supported", http.StatusBadRequest)
	}
}

// handlePasswordGrant handles the password grant type (username/password login)
func (a *APIAuth) handlePasswordGrant(w http.ResponseWriter, r *http.Request, req *TokenRequest) {
	if a.ValidateCredentials == nil {
		a.errorResponse(w, "server_error", "Authentication not configured", http.StatusInternalServerError)
		return
	}

	// Rate limiting check
	if a.RateLimiter != nil {
		key := getClientIP(r) + ":" + req.Username
		if !a.RateLimiter.Allow(key) {
			a.errorResponse(w, "rate_limit_exceeded", "Too many login attempts", http.StatusTooManyRequests)
			return
		}
	}

	// Validate credentials
	usernameType := DetectUsernameType(req.Username)
	user, err := a.ValidateCredentials(req.Username, req.Password, usernameType)
	if err != nil || user == nil {
		if a.OnLoginFailure != nil {
			a.OnLoginFailure(req.Username, r, err)
		}
		a.errorResponse(w, "invalid_grant", "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Get user's allowed scopes
	allowedScopes := []string{ScopeRead, ScopeWrite, ScopeProfile, ScopeOffline}
	if a.GetUserScopes != nil {
		var err error
		allowedScopes, err = a.GetUserScopes(user.Id())
		if err != nil {
			log.Printf("Error getting user scopes: %v", err)
			a.errorResponse(w, "server_error", "Failed to get user permissions", http.StatusInternalServerError)
			return
		}
	}

	// Parse and validate requested scopes
	requestedScopes := ParseScopes(req.Scope)
	if len(requestedScopes) == 0 {
		// If no scopes requested, grant all allowed scopes
		requestedScopes = allowedScopes
	}
	grantedScopes := IntersectScopes(requestedScopes, allowedScopes)

	// Extract device info for refresh token
	deviceInfo := map[string]any{
		"user_agent": r.UserAgent(),
		"ip":         getClientIP(r),
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}

	// Create refresh token
	refreshToken, err := a.RefreshTokenStore.CreateRefreshToken(
		user.Id(), req.ClientID, deviceInfo, grantedScopes)
	if err != nil {
		log.Printf("Error creating refresh token: %v", err)
		a.errorResponse(w, "server_error", "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Create access token (JWT)
	accessToken, expiresIn, err := a.createAccessToken(user.Id(), grantedScopes)
	if err != nil {
		log.Printf("Error creating access token: %v", err)
		a.errorResponse(w, "server_error", "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Call success callback
	if a.OnLoginSuccess != nil {
		a.OnLoginSuccess(user.Id(), r)
	}

	// Return token pair
	a.tokenResponse(w, accessToken, expiresIn, refreshToken.Token, grantedScopes)
}

// handleRefreshTokenGrant handles the refresh_token grant type
func (a *APIAuth) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, req *TokenRequest) {
	if req.RefreshToken == "" {
		a.errorResponse(w, "invalid_request", "Refresh token required", http.StatusBadRequest)
		return
	}

	// Get and validate refresh token
	refreshToken, err := a.RefreshTokenStore.GetRefreshToken(req.RefreshToken)
	if err != nil {
		if err == ErrTokenNotFound {
			a.errorResponse(w, "invalid_grant", "Invalid refresh token", http.StatusUnauthorized)
		} else {
			a.errorResponse(w, "server_error", "Failed to validate token", http.StatusInternalServerError)
		}
		return
	}

	// Check if revoked or expired
	if refreshToken.Revoked {
		a.errorResponse(w, "invalid_grant", "Token has been revoked", http.StatusUnauthorized)
		return
	}
	if refreshToken.IsExpired() {
		a.errorResponse(w, "invalid_grant", "Token has expired", http.StatusUnauthorized)
		return
	}

	// Rotate refresh token (creates new one, invalidates old)
	newRefreshToken, err := a.RefreshTokenStore.RotateRefreshToken(req.RefreshToken)
	if err != nil {
		if err == ErrTokenReused {
			// Token reuse detected - revoke entire family
			if revokeErr := a.RefreshTokenStore.RevokeTokenFamily(refreshToken.Family); revokeErr != nil {
				log.Printf("Error revoking token family: %v", revokeErr)
			}
			a.errorResponse(w, "invalid_grant", "Token reuse detected, all sessions revoked", http.StatusUnauthorized)
			return
		}
		log.Printf("Error rotating refresh token: %v", err)
		a.errorResponse(w, "server_error", "Failed to refresh session", http.StatusInternalServerError)
		return
	}

	// Create new access token
	accessToken, expiresIn, err := a.createAccessToken(refreshToken.UserID, refreshToken.Scopes)
	if err != nil {
		log.Printf("Error creating access token: %v", err)
		a.errorResponse(w, "server_error", "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Return new token pair
	a.tokenResponse(w, accessToken, expiresIn, newRefreshToken.Token, refreshToken.Scopes)
}

// HandleLogout handles POST /api/logout - revokes a refresh token
func (a *APIAuth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.errorResponse(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		a.errorResponse(w, "invalid_request", "Refresh token required", http.StatusBadRequest)
		return
	}

	// Revoke the token (ignore errors - don't reveal if token existed)
	if err := a.RefreshTokenStore.RevokeRefreshToken(req.RefreshToken); err != nil {
		log.Printf("Error revoking token: %v", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleLogoutAll handles POST /api/logout-all - revokes all refresh tokens for the user
// Requires authentication (userID must be in request context)
func (a *APIAuth) HandleLogoutAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.errorResponse(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user ID from context (set by middleware)
	userID := GetUserIDFromContext(r.Context())
	if userID == "" {
		a.errorResponse(w, "unauthorized", "Authentication required", http.StatusUnauthorized)
		return
	}

	// Revoke all user tokens
	if err := a.RefreshTokenStore.RevokeUserTokens(userID); err != nil {
		log.Printf("Error revoking user tokens: %v", err)
		a.errorResponse(w, "server_error", "Failed to revoke sessions", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleListSessions handles GET /api/sessions - lists active sessions for the user
// Requires authentication (userID must be in request context)
func (a *APIAuth) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.errorResponse(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user ID from context
	userID := GetUserIDFromContext(r.Context())
	if userID == "" {
		a.errorResponse(w, "unauthorized", "Authentication required", http.StatusUnauthorized)
		return
	}

	// Get user's active tokens
	tokens, err := a.RefreshTokenStore.GetUserTokens(userID)
	if err != nil {
		log.Printf("Error getting user tokens: %v", err)
		a.errorResponse(w, "server_error", "Failed to get sessions", http.StatusInternalServerError)
		return
	}

	// Build response with session info (hide sensitive data)
	type sessionInfo struct {
		ID         string    `json:"id"`
		DeviceInfo any       `json:"device_info,omitempty"`
		CreatedAt  time.Time `json:"created_at"`
		LastUsedAt time.Time `json:"last_used_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		Scopes     []string  `json:"scopes,omitempty"`
	}

	sessions := make([]sessionInfo, 0, len(tokens))
	for _, t := range tokens {
		sessions = append(sessions, sessionInfo{
			ID:         t.TokenHash[:16], // Use partial hash as ID
			DeviceInfo: t.DeviceInfo,
			CreatedAt:  t.CreatedAt,
			LastUsedAt: t.LastUsedAt,
			ExpiresAt:  t.ExpiresAt,
			Scopes:     t.Scopes,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sessions": sessions,
	})
}

// createAccessToken creates a signed JWT access token
func (a *APIAuth) createAccessToken(userID string, scopes []string) (string, int64, error) {
	expiry := a.AccessTokenExpiry
	if expiry == 0 {
		expiry = TokenExpiryAccessToken
	}

	now := time.Now()
	expiresAt := now.Add(expiry)

	claims := jwt.MapClaims{
		"sub":    userID,
		"type":   "access",
		"scopes": scopes,
		"iat":    now.Unix(),
		"exp":    expiresAt.Unix(),
	}

	if a.JWTIssuer != "" {
		claims["iss"] = a.JWTIssuer
	}
	if a.JWTAudience != "" {
		claims["aud"] = a.JWTAudience
	}

	signingMethod := jwt.SigningMethodHS256
	if a.JWTSigningAlg == "HS384" {
		signingMethod = jwt.SigningMethodHS384
	} else if a.JWTSigningAlg == "HS512" {
		signingMethod = jwt.SigningMethodHS512
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	tokenString, err := token.SignedString([]byte(a.JWTSecretKey))
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, int64(expiry.Seconds()), nil
}

// VerifyTokenFunc returns a function that can be used as Middleware.VerifyToken.
// This allows the Middleware to validate Bearer tokens using the APIAuth's JWT configuration.
func (a *APIAuth) VerifyTokenFunc() func(tokenString string) (userID string, token any, err error) {
	return func(tokenString string) (string, any, error) {
		userID, scopes, err := a.ValidateAccessToken(tokenString)
		if err != nil {
			return "", nil, err
		}
		return userID, scopes, nil
	}
}

// ValidateAccessToken validates a JWT access token and returns the claims
func (a *APIAuth) ValidateAccessToken(tokenString string) (userID string, scopes []string, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.JWTSecretKey), nil
	})

	if err != nil {
		return "", nil, err
	}

	if !token.Valid {
		return "", nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, fmt.Errorf("invalid claims")
	}

	// Verify token type
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
		return "", nil, fmt.Errorf("invalid token type")
	}

	// Verify issuer if configured
	if a.JWTIssuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != a.JWTIssuer {
			return "", nil, fmt.Errorf("invalid issuer")
		}
	}

	// Extract user ID
	userID, ok = claims["sub"].(string)
	if !ok || userID == "" {
		return "", nil, fmt.Errorf("missing subject")
	}

	// Extract scopes
	if scopesRaw, ok := claims["scopes"].([]any); ok {
		scopes = make([]string, 0, len(scopesRaw))
		for _, s := range scopesRaw {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	return userID, scopes, nil
}

// tokenResponse sends a successful token response
func (a *APIAuth) tokenResponse(w http.ResponseWriter, accessToken string, expiresIn int64, refreshToken string, scopes []string) {
	resp := TokenPair{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        JoinScopes(scopes),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// errorResponse sends an OAuth 2.0 compliant error response
func (a *APIAuth) errorResponse(w http.ResponseWriter, errorCode, description string, statusCode int) {
	resp := TokenError{
		Error:            errorCode,
		ErrorDescription: description,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// ============================================================================
// API Key Management Endpoints
// ============================================================================

// HandleAPIKeys handles API key management (GET=list, POST=create)
// Requires authentication (userID must be in request context)
func (a *APIAuth) HandleAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.handleListAPIKeys(w, r)
	case http.MethodPost:
		a.handleCreateAPIKey(w, r)
	default:
		a.errorResponse(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleListAPIKeys handles GET /api/keys - lists user's API keys
func (a *APIAuth) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID := GetUserIDFromContext(r.Context())
	if userID == "" {
		a.errorResponse(w, "unauthorized", "Authentication required", http.StatusUnauthorized)
		return
	}

	// Get user's API keys
	keys, err := a.APIKeyStore.ListUserAPIKeys(userID)
	if err != nil {
		log.Printf("Error listing API keys: %v", err)
		a.errorResponse(w, "server_error", "Failed to list API keys", http.StatusInternalServerError)
		return
	}

	// Build response (hide hashes)
	type apiKeyInfo struct {
		KeyID      string     `json:"key_id"`
		Name       string     `json:"name"`
		Scopes     []string   `json:"scopes,omitempty"`
		CreatedAt  time.Time  `json:"created_at"`
		ExpiresAt  *time.Time `json:"expires_at,omitempty"`
		LastUsedAt time.Time  `json:"last_used_at"`
		Revoked    bool       `json:"revoked"`
	}

	apiKeys := make([]apiKeyInfo, 0, len(keys))
	for _, k := range keys {
		apiKeys = append(apiKeys, apiKeyInfo{
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
	json.NewEncoder(w).Encode(map[string]any{
		"api_keys": apiKeys,
	})
}

// handleCreateAPIKey handles POST /api/keys - creates a new API key
func (a *APIAuth) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID := GetUserIDFromContext(r.Context())
	if userID == "" {
		a.errorResponse(w, "unauthorized", "Authentication required", http.StatusUnauthorized)
		return
	}

	// Parse request
	var req struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes,omitempty"`
		ExpiresIn int64    `json:"expires_in,omitempty"` // Seconds until expiry (0 = no expiry)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.errorResponse(w, "invalid_request", "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate name
	if req.Name == "" {
		a.errorResponse(w, "invalid_request", "Name is required", http.StatusBadRequest)
		return
	}

	// Validate and limit scopes
	allowedScopes := []string{ScopeRead, ScopeWrite, ScopeProfile}
	if a.GetUserScopes != nil {
		var err error
		allowedScopes, err = a.GetUserScopes(userID)
		if err != nil {
			log.Printf("Error getting user scopes: %v", err)
			a.errorResponse(w, "server_error", "Failed to get user permissions", http.StatusInternalServerError)
			return
		}
	}

	grantedScopes := req.Scopes
	if len(grantedScopes) == 0 {
		grantedScopes = allowedScopes
	} else {
		grantedScopes = IntersectScopes(req.Scopes, allowedScopes)
	}

	// Calculate expiry
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	// Create API key
	fullKey, apiKey, err := a.APIKeyStore.CreateAPIKey(userID, req.Name, grantedScopes, expiresAt)
	if err != nil {
		log.Printf("Error creating API key: %v", err)
		a.errorResponse(w, "server_error", "Failed to create API key", http.StatusInternalServerError)
		return
	}

	// Return response with full key (only shown once!)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"api_key":    fullKey, // This is the only time the full key is shown!
		"key_id":     apiKey.KeyID,
		"name":       apiKey.Name,
		"scopes":     apiKey.Scopes,
		"created_at": apiKey.CreatedAt,
		"expires_at": apiKey.ExpiresAt,
	})
}

// HandleRevokeAPIKey handles DELETE /api/keys/:id - revokes an API key
// Requires authentication (userID must be in request context)
func (a *APIAuth) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		a.errorResponse(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user ID from context
	userID := GetUserIDFromContext(r.Context())
	if userID == "" {
		a.errorResponse(w, "unauthorized", "Authentication required", http.StatusUnauthorized)
		return
	}

	// Extract key ID from URL path
	// Expected format: /api/keys/{keyID}
	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) == 0 {
		a.errorResponse(w, "invalid_request", "Key ID required", http.StatusBadRequest)
		return
	}
	keyID := parts[len(parts)-1]
	if keyID == "" || keyID == "keys" {
		a.errorResponse(w, "invalid_request", "Key ID required", http.StatusBadRequest)
		return
	}

	// Verify the key belongs to the user
	apiKey, err := a.APIKeyStore.GetAPIKeyByID(keyID)
	if err != nil {
		if err == ErrAPIKeyNotFound {
			a.errorResponse(w, "not_found", "API key not found", http.StatusNotFound)
		} else {
			a.errorResponse(w, "server_error", "Failed to get API key", http.StatusInternalServerError)
		}
		return
	}

	if apiKey.UserID != userID {
		a.errorResponse(w, "forbidden", "Not authorized to revoke this key", http.StatusForbidden)
		return
	}

	// Revoke the key
	if err := a.APIKeyStore.RevokeAPIKey(keyID); err != nil {
		log.Printf("Error revoking API key: %v", err)
		a.errorResponse(w, "server_error", "Failed to revoke API key", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// APIMiddleware - JWT and API Key validation middleware
// ============================================================================

// Context keys for API authentication
type apiContextKey string

const (
	contextKeyUserID   apiContextKey = "api_user_id"
	contextKeyScopes   apiContextKey = "api_scopes"
	contextKeyAuthType apiContextKey = "api_auth_type" // "jwt" or "api_key"
)

// APIMiddleware provides middleware for validating API tokens
type APIMiddleware struct {
	// JWT validation (uses same config as APIAuth)
	JWTSecretKey  string
	JWTIssuer     string
	JWTAudience   string
	JWTSigningAlg string

	// API key validation (optional)
	APIKeyStore APIKeyStore

	// Token header configuration
	AuthHeader string // Defaults to "Authorization"

	// Error handling
	OnAuthError func(w http.ResponseWriter, r *http.Request, err error)
}

// GetUserIDFromAPIContext retrieves the user ID from the API middleware context
func GetUserIDFromAPIContext(ctx context.Context) string {
	if v := ctx.Value(contextKeyUserID); v != nil {
		if userID, ok := v.(string); ok {
			return userID
		}
	}
	return ""
}

// GetScopesFromAPIContext retrieves the granted scopes from the API middleware context
func GetScopesFromAPIContext(ctx context.Context) []string {
	if v := ctx.Value(contextKeyScopes); v != nil {
		if scopes, ok := v.([]string); ok {
			return scopes
		}
	}
	return nil
}

// GetAuthTypeFromAPIContext retrieves the auth type ("jwt" or "api_key") from context
func GetAuthTypeFromAPIContext(ctx context.Context) string {
	if v := ctx.Value(contextKeyAuthType); v != nil {
		if authType, ok := v.(string); ok {
			return authType
		}
	}
	return ""
}

// ValidateToken middleware validates Bearer tokens (JWT or API key) and sets user info in context
func (m *APIMiddleware) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, scopes, authType, err := m.validateRequest(r)
		if err != nil {
			m.handleAuthError(w, r, err)
			return
		}

		// Set authenticated user info in context
		ctx := r.Context()
		ctx = context.WithValue(ctx, contextKeyUserID, userID)
		ctx = context.WithValue(ctx, contextKeyScopes, scopes)
		ctx = context.WithValue(ctx, contextKeyAuthType, authType)

		// Also set in the default context for compatibility
		ctx = SetUserIDInContext(ctx, userID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScopes middleware ensures the authenticated user has all required scopes
func (m *APIMiddleware) RequireScopes(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// First validate the token
			userID, grantedScopes, authType, err := m.validateRequest(r)
			if err != nil {
				m.handleAuthError(w, r, err)
				return
			}

			// Check if all required scopes are present
			if !ContainsAllScopes(grantedScopes, requiredScopes) {
				m.handleAuthError(w, r, fmt.Errorf("insufficient scope: requires %v", requiredScopes))
				return
			}

			// Set authenticated user info in context
			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeyUserID, userID)
			ctx = context.WithValue(ctx, contextKeyScopes, grantedScopes)
			ctx = context.WithValue(ctx, contextKeyAuthType, authType)
			ctx = SetUserIDInContext(ctx, userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Optional middleware allows requests without auth but sets user info if present
func (m *APIMiddleware) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, scopes, authType, err := m.validateRequest(r)
		if err == nil && userID != "" {
			// Set authenticated user info in context
			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeyUserID, userID)
			ctx = context.WithValue(ctx, contextKeyScopes, scopes)
			ctx = context.WithValue(ctx, contextKeyAuthType, authType)
			ctx = SetUserIDInContext(ctx, userID)
			r = r.WithContext(ctx)
		}
		// Continue even if not authenticated
		next.ServeHTTP(w, r)
	})
}

// validateRequest extracts and validates the token from the request
func (m *APIMiddleware) validateRequest(r *http.Request) (userID string, scopes []string, authType string, err error) {
	header := m.AuthHeader
	if header == "" {
		header = "Authorization"
	}

	authHeader := r.Header.Get(header)
	if authHeader == "" {
		return "", nil, "", fmt.Errorf("missing authorization header")
	}

	// Parse Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", nil, "", fmt.Errorf("invalid authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", nil, "", fmt.Errorf("empty token")
	}

	// Check if it's an API key (starts with "oa_")
	if strings.HasPrefix(token, "oa_") && m.APIKeyStore != nil {
		return m.validateAPIKey(token)
	}

	// Otherwise try JWT
	return m.validateJWT(token)
}

// validateJWT validates a JWT access token
func (m *APIMiddleware) validateJWT(tokenString string) (userID string, scopes []string, authType string, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.JWTSecretKey), nil
	})

	if err != nil {
		return "", nil, "", fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return "", nil, "", fmt.Errorf("token validation failed")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, "", fmt.Errorf("invalid claims")
	}

	// Verify token type
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
		return "", nil, "", fmt.Errorf("invalid token type")
	}

	// Verify issuer if configured
	if m.JWTIssuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != m.JWTIssuer {
			return "", nil, "", fmt.Errorf("invalid issuer")
		}
	}

	// Verify audience if configured
	if m.JWTAudience != "" {
		if aud, ok := claims["aud"].(string); !ok || aud != m.JWTAudience {
			return "", nil, "", fmt.Errorf("invalid audience")
		}
	}

	// Extract user ID
	userID, ok = claims["sub"].(string)
	if !ok || userID == "" {
		return "", nil, "", fmt.Errorf("missing subject")
	}

	// Extract scopes
	if scopesRaw, ok := claims["scopes"].([]any); ok {
		scopes = make([]string, 0, len(scopesRaw))
		for _, s := range scopesRaw {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	return userID, scopes, "jwt", nil
}

// validateAPIKey validates an API key
func (m *APIMiddleware) validateAPIKey(fullKey string) (userID string, scopes []string, authType string, err error) {
	apiKey, err := m.APIKeyStore.ValidateAPIKey(fullKey)
	if err != nil {
		return "", nil, "", fmt.Errorf("invalid API key: %w", err)
	}

	// Update last used timestamp (best effort, don't fail on error)
	go func() {
		if err := m.APIKeyStore.UpdateAPIKeyLastUsed(apiKey.KeyID); err != nil {
			log.Printf("Failed to update API key last used: %v", err)
		}
	}()

	return apiKey.UserID, apiKey.Scopes, "api_key", nil
}

// handleAuthError handles authentication errors
func (m *APIMiddleware) handleAuthError(w http.ResponseWriter, r *http.Request, err error) {
	if m.OnAuthError != nil {
		m.OnAuthError(w, r, err)
		return
	}

	// Default error response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": err.Error(),
	})
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return ip
}
