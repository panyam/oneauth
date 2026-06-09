package apiauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/tracing"
	"github.com/panyam/oneauth/utils"
)

// matchesAudience checks whether expectedAud appears in the JWT "aud" claim.
// Per RFC 7519 §4.1.3, "aud" may be a single string or an array of strings.
// Returns true if expectedAud matches the string value or is found in the array.
func matchesAudience(claims jwt.MapClaims, expectedAud string) bool {
	switch v := claims["aud"].(type) {
	case string:
		return v == expectedAud
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == expectedAud {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == expectedAud {
				return true
			}
		}
	}
	return false
}

// APIAuth handles API token-based authentication
type APIAuth struct {
	// Stores
	RefreshTokenStore core.RefreshTokenStore
	APIKeyStore       core.APIKeyStore

	// JWT configuration
	JWTSecretKey  string // Secret key for signing JWTs (HMAC)
	JWTIssuer     string // Issuer claim (e.g., "myapp")
	JWTAudience   string // Audience claim (e.g., "api")
	JWTSigningAlg string // Signing algorithm (defaults to HS256)

	// Asymmetric JWT keys (optional — when set, these take precedence over JWTSecretKey)
	JWTSigningKey any // crypto.PrivateKey (*rsa.PrivateKey or *ecdsa.PrivateKey) for signing
	JWTVerifyKey  any // crypto.PublicKey (*rsa.PublicKey or *ecdsa.PublicKey) for verification

	// Token configuration
	AccessTokenExpiry  time.Duration // Defaults to 15 minutes
	RefreshTokenExpiry time.Duration // Defaults to 7 days

	// Callbacks
	ValidateCredentials CredentialsValidator            // Validates username/password
	GetSubjectScopes    core.GetSubjectScopesFunc          // Returns allowed scopes for the subject (user ID or client_id)
	OnLoginSuccess      func(userID string, r *http.Request) // Optional: for logging/analytics
	OnLoginFailure      func(username string, r *http.Request, err error) // Optional: for logging/analytics

	// CustomClaimsFunc is called during token creation to inject additional claims
	// into the JWT (e.g., client_id, max_rooms for relay-scoped tokens).
	// Standard claims (sub, iss, aud, exp, iat, type, scopes) cannot be overridden.
	// If nil, no custom claims are added (backwards-compatible).
	CustomClaimsFunc func(userID string, scopes []string) (map[string]any, error)

	// ClientKeyStore provides client credential lookup for the client_credentials
	// grant type (RFC 6749 §4.4). When set, the token endpoint accepts
	// grant_type=client_credentials and authenticates clients via KeyStore.
	// When nil, client_credentials requests return unsupported_grant_type.
	ClientKeyStore keys.KeyLookup

	// ClientAuthenticator authenticates clients at the token endpoint
	// (and is also used by the introspection / revocation handlers).
	// When set, all client authentication on the token endpoint
	// (client_secret_basic, client_secret_post, private_key_jwt) goes
	// through this interface — supporting the assertion-based methods
	// is the entire point of plumbing it here. When nil, the token
	// endpoint falls back to the legacy inline lookup against
	// ClientKeyStore (secret-based methods only).
	ClientAuthenticator ClientAuthenticator

	// AcceptedAudiences are the URLs the AS will accept as the `aud`
	// claim of a private_key_jwt / client_secret_jwt client assertion
	// at the token endpoint (OIDC Core §9). Typically the token
	// endpoint URL plus the AS issuer URL. When empty, the URL of the
	// request is used as a fallback (single-host deployments only).
	AcceptedAudiences []string

	// lazyAuthenticator caches the authenticator built from
	// ClientKeyStore when ClientAuthenticator was not wired
	// explicitly. The cache is critical: a fresh authenticator per
	// request means a fresh in-memory JTIStore, which would defeat
	// replay protection for private_key_jwt assertions.
	lazyAuthenticator     ClientAuthenticator
	lazyAuthenticatorOnce sync.Once

	// lazyIssuer / lazyValidator cache the gRPC-shape TokenIssuer /
	// TokenValidator built from APIAuth's configuration. They are the
	// implementations every HTTP handler dispatches through. Lazy so
	// callers can populate APIAuth fields after construction (the
	// existing usage pattern) before any token is minted.
	lazyIssuer        TokenIssuer
	lazyIssuerOnce    sync.Once
	lazyValidator     TokenValidator
	lazyValidatorOnce sync.Once

	// TrustedAssertionIssuers lists upstream IdPs whose JWT assertions
	// the token endpoint will accept for the jwt-bearer grant
	// (RFC 7523 §2.1) and the token-exchange grant with
	// subject_token_type=urn:ietf:params:oauth:token-type:jwt
	// (RFC 8693 §2.1.1). When empty, both grants return
	// unsupported_grant_type.
	//
	// See JwtBearerGrantType, TokenExchangeGrantType, and
	// TrustedAssertionIssuer for details.
	TrustedAssertionIssuers []TrustedAssertionIssuer

	// Rate limiting (optional)
	RateLimiter core.RateLimiter

	// Blacklist enables immediate access token revocation. When set,
	// ValidateAccessToken checks the blacklist after signature verification.
	// Tokens include a jti (JWT ID) claim for blacklist lookup.
	// If nil, tokens are validated by signature + expiry only (stateless).
	Blacklist core.TokenBlacklist

	// TokenHooks fires on token lifecycle events handled directly by APIAuth
	// (logout / logout-all). The HTTP-facing APIAuth is wired field-by-field
	// rather than via OneAuthConfig; callers who want logout-all to drive
	// the OIDC Back-Channel Logout dispatcher must populate
	// TokenHooks.OnSubjectRevoked here. Leaving it zero keeps HandleLogout /
	// HandleLogoutAll behaviorally unchanged.
	TokenHooks TokenHooks

	// DeviceAuthStore enables the RFC 8628 device authorization grant.
	// When non-nil the token endpoint accepts
	// grant_type=urn:ietf:params:oauth:grant-type:device_code and the
	// caller is expected to mount DeviceAuthorizationHandler at the
	// /device/authorize path. Nil keeps the token endpoint behaviorally
	// identical to its pre-#117 surface.
	DeviceAuthStore core.DeviceAuthorizationStore

	// TracerProvider opts the /token endpoint into SEP-414 tracing.
	// When set, ServeHTTP extracts an inbound W3C `traceparent` header
	// and emits a single `oneauth.token.issue` span with the parsed
	// grant type as an attribute. Nil keeps the handler on the no-op
	// fast path. The same TracerProvider should usually be passed to
	// IntrospectionHandler, RevocationHandler, JWKSHandler, and the
	// JWKSKeyStore so all spans share one trace.
	TracerProvider trace.TracerProvider
}

// ServeHTTP handles the /api/token endpoint. It accepts both
// application/x-www-form-urlencoded (RFC 6749 standard) and
// application/json request bodies.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2
func (a *APIAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracing.Tracer(a.TracerProvider, tracing.InstrumentationName).
		Start(tracing.Extract(r), "oneauth.token.issue", trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	r = r.WithContext(ctx)

	if r.Method != http.MethodPost {
		span.SetStatus(codes.Error, "method not allowed")
		a.errorResponse(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body — support both form-encoded (RFC 6749) and JSON
	var req core.TokenRequest
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			a.errorResponse(w, "invalid_request", "Invalid form body", http.StatusBadRequest)
			return
		}
		req = core.TokenRequest{
			GrantType:    r.FormValue("grant_type"),
			Username:     r.FormValue("username"),
			Password:     r.FormValue("password"),
			RefreshToken: r.FormValue("refresh_token"),
			Scope:        r.FormValue("scope"),
			ClientID:     r.FormValue("client_id"),
			ClientSecret: r.FormValue("client_secret"),
			DeviceCode:   r.FormValue("device_code"),
			// RFC 7521 §4.2 / RFC 7523 §2.2 — client authentication
			// via signed JWT (private_key_jwt / client_secret_jwt).
			ClientAssertionType: r.FormValue("client_assertion_type"),
			ClientAssertion:     r.FormValue("client_assertion"),
			// RFC 7523 §2.1 — jwt-bearer authorization grant
			Assertion: r.FormValue("assertion"),
			// RFC 8693 — token exchange
			SubjectToken:       r.FormValue("subject_token"),
			SubjectTokenType:   r.FormValue("subject_token_type"),
			RequestedTokenType: r.FormValue("requested_token_type"),
			Resource:           r.FormValue("resource"),
			Audience:           r.FormValue("audience"),
		}
		// RFC 9396 §6.1: authorization_details is a JSON-encoded string in form params
		if adStr := r.FormValue("authorization_details"); adStr != "" {
			if err := json.Unmarshal([]byte(adStr), &req.AuthorizationDetails); err != nil {
				a.errorResponse(w, "invalid_authorization_details", "Invalid authorization_details JSON", http.StatusBadRequest)
				return
			}
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.errorResponse(w, "invalid_request", "Invalid request body", http.StatusBadRequest)
			return
		}
	}

	span.SetAttributes(attribute.String("oauth.grant_type", req.GrantType))

	// Handle based on grant type
	switch req.GrantType {
	case "password":
		a.handlePasswordGrant(w, r, &req)
	case "refresh_token":
		a.handleRefreshTokenGrant(w, r, &req)
	case "client_credentials":
		a.handleClientCredentialsGrant(w, r, &req)
	case JwtBearerGrantType:
		a.handleJwtBearerGrant(w, r, &req)
	case TokenExchangeGrantType:
		a.handleTokenExchangeGrant(w, r, &req)
	case DeviceCodeGrantType:
		a.handleDeviceCodeGrant(w, r, &req)
	default:
		span.SetStatus(codes.Error, "unsupported_grant_type")
		a.errorResponse(w, "unsupported_grant_type", "Grant type not supported", http.StatusBadRequest)
	}
}

// handlePasswordGrant handles the password grant type (username/password login)
func (a *APIAuth) handlePasswordGrant(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
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
	usernameType := accounts.DetectUsernameType(req.Username)
	user, err := a.ValidateCredentials(req.Username, req.Password, usernameType)
	if err != nil || user == nil {
		if a.OnLoginFailure != nil {
			a.OnLoginFailure(req.Username, r, err)
		}
		a.errorResponse(w, "invalid_grant", "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Get user's allowed scopes
	allowedScopes := []string{core.ScopeRead, core.ScopeWrite, core.ScopeProfile, core.ScopeOffline}
	if a.GetSubjectScopes != nil {
		var err error
		allowedScopes, err = a.GetSubjectScopes(user.Id())
		if err != nil {
			log.Printf("Error getting user scopes: %v", err)
			a.errorResponse(w, "server_error", "Failed to get user permissions", http.StatusInternalServerError)
			return
		}
	}

	// Parse and validate requested scopes
	requestedScopes := core.ParseScopes(req.Scope)
	if len(requestedScopes) == 0 {
		// If no scopes requested, grant all allowed scopes
		requestedScopes = allowedScopes
	}
	grantedScopes := core.IntersectScopes(requestedScopes, allowedScopes)

	// Extract device info for refresh token
	deviceInfo := map[string]any{
		"user_agent": r.UserAgent(),
		"ip":         getClientIP(r),
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}

	// Create refresh token
	createResp, err := a.RefreshTokenStore.CreateRefreshToken(r.Context(), &core.CreateRefreshTokenRequest{
		Subject:    user.Id(),
		ClientID:   req.ClientID,
		DeviceInfo: deviceInfo,
		Scopes:     grantedScopes,
	})
	if err != nil {
		log.Printf("Error creating refresh token: %v", err)
		a.errorResponse(w, "server_error", "Failed to create session", http.StatusInternalServerError)
		return
	}
	refreshToken := createResp.Token

	// Validate authorization_details if present (RFC 9396)
	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		a.errorResponse(w, "invalid_authorization_details", err.Error(), http.StatusBadRequest)
		return
	}

	// Create access token (JWT)
	tokResp, err := a.Issuer().CreateAccessToken(r.Context(), &CreateAccessTokenRequest{
		Subject:              user.Id(),
		Scopes:               grantedScopes,
		AuthorizationDetails: req.AuthorizationDetails,
	})
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
	a.tokenResponse(w, tokResp.Token, tokResp.ExpiresIn, refreshToken.Token, grantedScopes, req.AuthorizationDetails)
}

// handleRefreshTokenGrant handles the refresh_token grant type
func (a *APIAuth) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if req.RefreshToken == "" {
		a.errorResponse(w, "invalid_request", "Refresh token required", http.StatusBadRequest)
		return
	}

	// Get and validate refresh token
	getResp, err := a.RefreshTokenStore.GetRefreshToken(r.Context(), &core.GetRefreshTokenRequest{Token: req.RefreshToken})
	if err != nil {
		if err == core.ErrTokenNotFound {
			a.errorResponse(w, "invalid_grant", "Invalid refresh token", http.StatusUnauthorized)
		} else {
			a.errorResponse(w, "server_error", "Failed to validate token", http.StatusInternalServerError)
		}
		return
	}
	refreshToken := getResp.Token

	// Check if revoked — this indicates token reuse (theft detection).
	// Revoke the entire token family to invalidate all related sessions.
	if refreshToken.Revoked {
		if _, revokeErr := a.RefreshTokenStore.RevokeTokenFamily(r.Context(), &core.RevokeTokenFamilyRequest{Family: refreshToken.Family}); revokeErr != nil {
			log.Printf("Error revoking token family on reuse: %v", revokeErr)
		}
		a.errorResponse(w, "invalid_grant", "Token reuse detected, all sessions revoked", http.StatusUnauthorized)
		return
	}
	if refreshToken.IsExpired() {
		a.errorResponse(w, "invalid_grant", "Token has expired", http.StatusUnauthorized)
		return
	}

	// Rotate refresh token (creates new one, invalidates old)
	rotResp, err := a.RefreshTokenStore.RotateRefreshToken(r.Context(), &core.RotateRefreshTokenRequest{OldToken: req.RefreshToken})
	if err != nil {
		if err == core.ErrTokenReused {
			// Token reuse detected - revoke entire family
			if _, revokeErr := a.RefreshTokenStore.RevokeTokenFamily(r.Context(), &core.RevokeTokenFamilyRequest{Family: refreshToken.Family}); revokeErr != nil {
				log.Printf("Error revoking token family: %v", revokeErr)
			}
			a.errorResponse(w, "invalid_grant", "Token reuse detected, all sessions revoked", http.StatusUnauthorized)
			return
		}
		log.Printf("Error rotating refresh token: %v", err)
		a.errorResponse(w, "server_error", "Failed to refresh session", http.StatusInternalServerError)
		return
	}
	newRefreshToken := rotResp.Token

	// Create new access token (carry forward authorization_details from original grant)
	tokResp, err := a.Issuer().CreateAccessToken(r.Context(), &CreateAccessTokenRequest{
		Subject:              refreshToken.Subject,
		Scopes:               refreshToken.Scopes,
		AuthorizationDetails: refreshToken.AuthorizationDetails,
	})
	if err != nil {
		log.Printf("Error creating access token: %v", err)
		a.errorResponse(w, "server_error", "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Return new token pair
	a.tokenResponse(w, tokResp.Token, tokResp.ExpiresIn, newRefreshToken.Token, refreshToken.Scopes, refreshToken.AuthorizationDetails)
}

// handleClientCredentialsGrant handles the client_credentials grant type (RFC 6749 §4.4).
// Machine-to-machine authentication: the client authenticates with one of
// the registered token-endpoint auth methods and receives an access token
// with sub=client_id. No user context, no refresh token.
//
// Client authentication methods (selected automatically by which credentials
// are present on the request):
//   - client_secret_basic: HTTP Basic auth with client_id:client_secret
//   - client_secret_post:  client_id + client_secret in the form body
//   - private_key_jwt:     client_assertion_type + client_assertion (RFC 7523 §2.2)
func (a *APIAuth) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if a.ClientKeyStore == nil && a.ClientAuthenticator == nil {
		a.errorResponse(w, "unsupported_grant_type", "client_credentials not configured", http.StatusBadRequest)
		return
	}

	clientID, err := a.authenticateTokenEndpointClient(r, req)
	if err != nil {
		log.Printf("client_credentials auth failed: %v", err)
		// errMissingClientCredentials → 400 invalid_request
		// (RFC 6749 §5.2 — missing required parameter).
		// All other auth failures (bad secret, bad assertion,
		// unknown client) → 401 invalid_client.
		if errors.Is(err, errMissingClientCredentials) {
			a.errorResponse(w, "invalid_request", err.Error(), http.StatusBadRequest)
			return
		}
		a.errorResponse(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Parse requested scopes
	var scopes []string
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}

	// Validate authorization_details if present (RFC 9396)
	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		a.errorResponse(w, "invalid_authorization_details", err.Error(), http.StatusBadRequest)
		return
	}

	// Create access token with sub=client_id (no user context)
	tokResp, err := a.Issuer().CreateAccessToken(r.Context(), &CreateAccessTokenRequest{
		Subject:              clientID,
		Scopes:               scopes,
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		log.Printf("Error creating client_credentials token: %v", err)
		a.errorResponse(w, "server_error", "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Return access token only — no refresh token for client_credentials
	a.tokenResponse(w, tokResp.Token, tokResp.ExpiresIn, "", scopes, req.AuthorizationDetails)
}

// authenticateTokenEndpointClient runs whichever auth method the request
// carries. Routes through ClientAuthenticator when set (the only path
// that supports private_key_jwt); falls back to inline secret-only
// lookup against ClientKeyStore for backward compatibility with
// callers that don't wire an authenticator.
func (a *APIAuth) authenticateTokenEndpointClient(r *http.Request, req *core.TokenRequest) (string, error) {
	auth := a.ClientAuthenticator
	if auth == nil && a.ClientKeyStore != nil {
		// Lazily build (and cache) an authenticator over ClientKeyStore
		// so legacy callers automatically gain private_key_jwt support
		// once they register asymmetric-keyed clients. Caching is
		// required for jti replay protection — a fresh authenticator
		// per request means a fresh JTIStore.
		a.lazyAuthenticatorOnce.Do(func() {
			a.lazyAuthenticator = NewClientAuthenticator(a.ClientKeyStore)
		})
		auth = a.lazyAuthenticator
	}
	if auth == nil {
		return "", fmt.Errorf("no client authenticator configured")
	}

	creds, ok := extractClientCredentials(r, req)
	if !ok {
		return "", errMissingClientCredentials
	}
	creds.Audiences = a.AcceptedAudiences
	if len(creds.Audiences) == 0 {
		creds.Audiences = []string{derivedAudience(r)}
	}
	resp, err := auth.AuthenticateClient(r.Context(), creds)
	if err != nil {
		return "", err
	}
	if resp == nil || resp.ClientID == "" {
		return "", fmt.Errorf("authenticator returned empty ClientID")
	}
	return resp.ClientID, nil
}

// constantTimeEqual performs a constant-time string comparison to prevent
// timing attacks on client secret validation.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		// Still do a comparison to keep timing constant-ish
		// (length leak is acceptable for secret comparison)
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
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

	// Capture subject + family + client_id BEFORE revoke so the BCL
	// dispatcher can be told who to notify. We deliberately Get-then-Revoke
	// rather than RevokeAndReturn — the store interface doesn't expose the
	// latter, and a missing token leaves all three fields empty which the
	// dispatcher already handles.
	var sub, sid, clientID string
	if getResp, err := a.RefreshTokenStore.GetRefreshToken(r.Context(), &core.GetRefreshTokenRequest{Token: req.RefreshToken}); err == nil && getResp != nil && getResp.Token != nil {
		sub = getResp.Token.Subject
		sid = getResp.Token.Family
		clientID = getResp.Token.ClientID
	}

	// Revoke the token (ignore errors - don't reveal if token existed)
	if _, err := a.RefreshTokenStore.RevokeRefreshToken(r.Context(), &core.RevokeRefreshTokenRequest{Token: req.RefreshToken}); err != nil {
		log.Printf("Error revoking token: %v", err)
	}

	if sub != "" {
		a.TokenHooks.fireOnTokenRevoked(sub, sid, clientID)
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
	userID := core.GetSubjectFromContext(r.Context())
	if userID == "" {
		a.errorResponse(w, "unauthorized", "Authentication required", http.StatusUnauthorized)
		return
	}

	// Capture the affected client_ids BEFORE revoke so the OIDC Back-Channel
	// Logout dispatcher knows who to notify — RefreshTokenStore.GetSubjectTokens
	// returns only active grants and would yield an empty set if called after
	// RevokeSubjectTokens. Empty list when no client ever associated with the
	// user's tokens.
	var clientIDs []string
	if getResp, err := a.RefreshTokenStore.GetSubjectTokens(r.Context(), &core.GetSubjectTokensRequest{Subject: userID}); err == nil && getResp != nil {
		seen := map[string]struct{}{}
		for _, t := range getResp.Tokens {
			if t == nil || t.ClientID == "" {
				continue
			}
			if _, ok := seen[t.ClientID]; ok {
				continue
			}
			seen[t.ClientID] = struct{}{}
			clientIDs = append(clientIDs, t.ClientID)
		}
	}

	// Revoke all user tokens
	if _, err := a.RefreshTokenStore.RevokeSubjectTokens(r.Context(), &core.RevokeSubjectTokensRequest{Subject: userID}); err != nil {
		log.Printf("Error revoking user tokens: %v", err)
		a.errorResponse(w, "server_error", "Failed to revoke sessions", http.StatusInternalServerError)
		return
	}

	// Fire the subject-scoped revoke hook so the BCL dispatcher (and any
	// other subscriber) can fan out OIDC logout notifications. sid is empty
	// here — logout-all crosses every session for the user.
	a.TokenHooks.fireOnSubjectRevoked(userID, "", clientIDs)

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
	userID := core.GetSubjectFromContext(r.Context())
	if userID == "" {
		a.errorResponse(w, "unauthorized", "Authentication required", http.StatusUnauthorized)
		return
	}

	// Get user's active tokens
	getResp, err := a.RefreshTokenStore.GetSubjectTokens(r.Context(), &core.GetSubjectTokensRequest{Subject: userID})
	if err != nil {
		log.Printf("Error getting user tokens: %v", err)
		a.errorResponse(w, "server_error", "Failed to get sessions", http.StatusInternalServerError)
		return
	}
	tokens := getResp.Tokens

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

// standardClaims is the set of JWT claim keys that cannot be overridden by CustomClaimsFunc.
var standardClaims = map[string]bool{
	"sub": true, "iss": true, "aud": true, "exp": true,
	"iat": true, "type": true, "scopes": true, "jti": true,
	"authorization_details": true, // RFC 9396
}

// Issuer returns the TokenIssuer implementation backing APIAuth's token-mint
// HTTP handlers. Lazily built from APIAuth's configuration on first call;
// safe for use after all APIAuth fields are populated.
func (a *APIAuth) Issuer() TokenIssuer {
	a.lazyIssuerOnce.Do(func() {
		a.lazyIssuer = NewJWTIssuer(JWTIssuerConfig{
			SigningKey:          a.signingKeyForIssuer(),
			SigningAlg:          a.signingAlg(),
			Issuer:              a.JWTIssuer,
			Audience:            a.JWTAudience,
			AccessExpiry:        a.AccessTokenExpiry,
			ClientKeyLookup:     a.ClientKeyStore,
			RefreshStore:        a.RefreshTokenStore,
			ValidateCredentials: a.ValidateCredentials,
			GetSubjectScopes:    a.GetSubjectScopes,
			CustomClaims:        CustomClaimsFunc(a.CustomClaimsFunc),
		})
	})
	return a.lazyIssuer
}

// Validator returns the TokenValidator implementation backing APIAuth's
// token-validation paths (middleware, introspection). Lazily built from
// APIAuth's configuration on first call.
func (a *APIAuth) Validator() TokenValidator {
	a.lazyValidatorOnce.Do(func() {
		a.lazyValidator = NewJWTValidator(JWTValidatorConfig{
			SigningKey:     a.signingKeyForValidator(),
			SigningAlg:     a.signingAlg(),
			Blacklist:      a.Blacklist,
			Issuer:         a.JWTIssuer,
			Audience:       a.JWTAudience,
			TracerProvider: a.TracerProvider,
		})
	})
	return a.lazyValidator
}

// signingAlg returns APIAuth's effective signing algorithm, defaulting to HS256.
func (a *APIAuth) signingAlg() string {
	if a.JWTSigningAlg != "" {
		return a.JWTSigningAlg
	}
	return "HS256"
}

// signingKeyForIssuer returns the key used for signing new tokens.
// Asymmetric (JWTSigningKey) takes precedence over symmetric (JWTSecretKey).
func (a *APIAuth) signingKeyForIssuer() any {
	if a.JWTSigningKey != nil {
		return a.JWTSigningKey
	}
	return []byte(a.JWTSecretKey)
}

// signingKeyForValidator returns the key used for verifying token signatures.
// For asymmetric algorithms, this is the public verification key; for HMAC,
// the same secret used to sign.
func (a *APIAuth) signingKeyForValidator() any {
	if a.JWTVerifyKey != nil {
		return a.JWTVerifyKey
	}
	if a.JWTSigningKey != nil {
		// Asymmetric mode without an explicit verify key — most code paths
		// pass both, but fall back to the signing key so HS256 holders that
		// set only JWTSigningKey still work.
		return a.JWTSigningKey
	}
	return []byte(a.JWTSecretKey)
}

// tokenResponse sends a successful token response
func (a *APIAuth) tokenResponse(w http.ResponseWriter, accessToken string, expiresIn int64, refreshToken string, scopes []string, authzDetails []core.AuthorizationDetail) {
	resp := core.TokenPair{
		AccessToken:          accessToken,
		TokenType:            "Bearer",
		ExpiresIn:            expiresIn,
		RefreshToken:         refreshToken,
		Scope:                core.JoinScopes(scopes),
		AuthorizationDetails: authzDetails,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// errorResponse sends an OAuth 2.0 compliant error response
func (a *APIAuth) errorResponse(w http.ResponseWriter, errorCode, description string, statusCode int) {
	resp := core.TokenError{
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
	userID := core.GetSubjectFromContext(r.Context())
	if userID == "" {
		a.errorResponse(w, "unauthorized", "Authentication required", http.StatusUnauthorized)
		return
	}

	// Get user's API keys
	listResp, err := a.APIKeyStore.ListSubjectAPIKeys(r.Context(), &core.ListSubjectAPIKeysRequest{Subject: userID})
	if err != nil {
		log.Printf("Error listing API keys: %v", err)
		a.errorResponse(w, "server_error", "Failed to list API keys", http.StatusInternalServerError)
		return
	}
	keys := listResp.APIKeys

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
	userID := core.GetSubjectFromContext(r.Context())
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
	allowedScopes := []string{core.ScopeRead, core.ScopeWrite, core.ScopeProfile}
	if a.GetSubjectScopes != nil {
		var err error
		allowedScopes, err = a.GetSubjectScopes(userID)
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
		grantedScopes = core.IntersectScopes(req.Scopes, allowedScopes)
	}

	// Calculate expiry
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	// Create API key
	createResp, err := a.APIKeyStore.CreateAPIKey(r.Context(), &core.CreateAPIKeyRequest{
		Subject:   userID,
		Name:      req.Name,
		Scopes:    grantedScopes,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		log.Printf("Error creating API key: %v", err)
		a.errorResponse(w, "server_error", "Failed to create API key", http.StatusInternalServerError)
		return
	}
	apiKey := createResp.APIKey

	// Return response with full key (only shown once!)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"api_key":    createResp.FullKey, // This is the only time the full key is shown!
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
	userID := core.GetSubjectFromContext(r.Context())
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
	getResp, err := a.APIKeyStore.GetAPIKeyByID(r.Context(), &core.GetAPIKeyByIDRequest{KeyID: keyID})
	if err != nil {
		if err == core.ErrAPIKeyNotFound {
			a.errorResponse(w, "not_found", "API key not found", http.StatusNotFound)
		} else {
			a.errorResponse(w, "server_error", "Failed to get API key", http.StatusInternalServerError)
		}
		return
	}

	if getResp.APIKey.Subject != userID {
		a.errorResponse(w, "forbidden", "Not authorized to revoke this key", http.StatusForbidden)
		return
	}

	// Revoke the key
	if _, err := a.APIKeyStore.RevokeAPIKey(r.Context(), &core.RevokeAPIKeyRequest{KeyID: keyID}); err != nil {
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
	contextKeySubject               apiContextKey = "api_user_id"
	contextKeyScopes               apiContextKey = "api_scopes"
	contextKeyAuthType             apiContextKey = "api_auth_type" // "jwt" or "api_key"
	contextKeyCustomClaims         apiContextKey = "api_custom_claims"
	contextKeyAuthorizationDetails apiContextKey = "api_authorization_details" // RFC 9396
)

// APIMiddleware provides middleware for validating API tokens
type APIMiddleware struct {
	// JWT validation (uses same config as APIAuth)
	JWTSecretKey  string
	JWTIssuer     string
	JWTAudience   string
	JWTSigningAlg string

	// KeyStore for multi-tenant JWT validation. When set, the middleware uses
	// GetKeyByKid (for tokens with kid header) or GetKey (for client_id claim).
	// When nil, falls back to JWTSecretKey (single-tenant, backwards-compatible).
	KeyStore keys.KeyLookup

	// API key validation (optional)
	APIKeyStore core.APIKeyStore

	// Token header configuration
	AuthHeader string // Defaults to "Authorization"

	// TokenQueryParam is the query parameter name to check for a token as fallback
	// when the Authorization header is missing (e.g., "token" for ?token=...).
	// Empty string disables query param extraction (default).
	TokenQueryParam string

	// Error handling
	OnAuthError func(w http.ResponseWriter, r *http.Request, err error)

	// Blacklist enables immediate access token revocation. When set,
	// validateJWT checks the blacklist after signature verification.
	// If nil, no revocation check (stateless validation only).
	Blacklist core.TokenBlacklist

	// Introspection enables token validation via a remote introspection
	// endpoint (RFC 7662) as an alternative to local JWT/JWKS validation.
	// When set, tokens that fail local validation are sent to the
	// introspection endpoint. When local validation is not configured
	// (no JWTSecretKey, no KeyStore), introspection is the only validation path.
	// If nil, only local validation is used.
	Introspection *IntrospectionValidator

	// Validator is the transport-independent token validator (Phase 2).
	// When set, validateJWT delegates to it instead of using inline logic.
	// When nil, a validator is lazily built from the existing fields
	// (JWTSecretKey, KeyStore, Blacklist, etc.) on first use.
	Validator TokenValidator

	// TracerProvider opts the resource-server validation path into
	// SEP-414 tracing. When set, the lazily-built validator emits
	// `oneauth.signature_verify` spans, and the lookup-by-kid call
	// against KeyStore inherits the same trace context. Nil keeps
	// validation on the no-op fast path.
	TracerProvider trace.TracerProvider

	// validatorOnce ensures the lazy validator is built only once.
	validatorOnce sync.Once
	lazyValidator TokenValidator
}

// GetSubjectFromAPIContext retrieves the authenticated subject (RFC 7519
// `sub` — user ID for human-driven flows, client_id for
// client_credentials) from the API middleware context.
func GetSubjectFromAPIContext(ctx context.Context) string {
	if v := ctx.Value(contextKeySubject); v != nil {
		if subject, ok := v.(string); ok {
			return subject
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

// GetCustomClaimsFromContext retrieves the custom (non-standard) JWT claims from context.
// Returns nil if no custom claims are present (e.g., API key auth or no token).
func GetCustomClaimsFromContext(ctx context.Context) map[string]any {
	if v := ctx.Value(contextKeyCustomClaims); v != nil {
		if claims, ok := v.(map[string]any); ok {
			return claims
		}
	}
	return nil
}

// GetAuthorizationDetailsFromContext retrieves the RFC 9396 authorization_details from context.
// Returns nil if no authorization details are present (e.g., API key auth or token without RAR).
func GetAuthorizationDetailsFromContext(ctx context.Context) []core.AuthorizationDetail {
	if v := ctx.Value(contextKeyAuthorizationDetails); v != nil {
		if details, ok := v.([]core.AuthorizationDetail); ok {
			return details
		}
	}
	return nil
}

// ValidateToken middleware validates Bearer tokens (JWT or API key) and sets user info in context
func (m *APIMiddleware) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, scopes, authType, customClaims, err := m.validateRequest(r)
		if err != nil {
			m.handleAuthError(w, r, err)
			return
		}

		ctx := setAuthContext(r.Context(), userID, scopes, authType, customClaims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScopes middleware ensures the authenticated user has all required scopes
func (m *APIMiddleware) RequireScopes(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, grantedScopes, authType, customClaims, err := m.validateRequest(r)
			if err != nil {
				m.handleAuthError(w, r, err)
				return
			}

			if !core.ContainsAllScopes(grantedScopes, requiredScopes) {
				m.handleAuthError(w, r, fmt.Errorf("insufficient scope: requires %v", requiredScopes))
				return
			}

			ctx := setAuthContext(r.Context(), userID, grantedScopes, authType, customClaims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Optional middleware allows requests without auth but sets user info if present
func (m *APIMiddleware) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, scopes, authType, customClaims, err := m.validateRequest(r)
		if err == nil && userID != "" {
			ctx := setAuthContext(r.Context(), userID, scopes, authType, customClaims)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// validateRequest extracts and validates the token from the request
func (m *APIMiddleware) validateRequest(r *http.Request) (userID string, scopes []string, authType string, customClaims map[string]any, err error) {
	header := m.AuthHeader
	if header == "" {
		header = "Authorization"
	}

	authHeader := r.Header.Get(header)

	// Fallback to query param if no header and TokenQueryParam is configured
	if authHeader == "" && m.TokenQueryParam != "" {
		if qp := r.URL.Query().Get(m.TokenQueryParam); qp != "" {
			authHeader = "Bearer " + qp
		}
	}

	if authHeader == "" {
		return "", nil, "", nil, fmt.Errorf("missing authorization header")
	}

	// Parse Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", nil, "", nil, fmt.Errorf("invalid authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", nil, "", nil, fmt.Errorf("empty token")
	}

	// Check if it's an API key (starts with "oa_")
	if strings.HasPrefix(token, "oa_") && m.APIKeyStore != nil {
		userID, scopes, authType, err := m.validateAPIKey(r.Context(), token)
		return userID, scopes, authType, nil, err
	}

	// Try local JWT validation first
	userID, scopes, authType, customClaims, jwtErr := m.validateJWT(r.Context(), token)
	if jwtErr == nil {
		return userID, scopes, authType, customClaims, nil
	}

	// If local validation failed and introspection is configured, try that
	if m.Introspection != nil {
		return m.Introspection.ValidateForMiddlewareWithContext(r.Context(), token)
	}

	// No introspection fallback — return the original JWT error
	return "", nil, "", nil, jwtErr
}

// getValidator returns the TokenValidator, lazily building one from existing
// fields if Validator is not explicitly set.
func (m *APIMiddleware) getValidator() TokenValidator {
	if m.Validator != nil {
		return m.Validator
	}
	m.validatorOnce.Do(func() {
		if m.KeyStore != nil {
			// Multi-tenant: use KeyStore for kid/client_id-based lookup
			m.lazyValidator = NewJWTValidator(JWTValidatorConfig{
				KeyLookup:      m.KeyStore,
				Blacklist:      m.Blacklist,
				Issuer:         m.JWTIssuer,
				Audience:       m.JWTAudience,
				TracerProvider: m.TracerProvider,
			})
		} else {
			// Single-tenant: can't use jwtValidator (it needs kid/client_id lookup).
			// Fall back to the original inline validation which handles JWTSecretKey directly.
			m.lazyValidator = nil
		}
	})
	return m.lazyValidator
}

// validateJWT validates a JWT access token using the TokenValidator. The
// caller's ctx (typically the inbound request's context) is forwarded
// into ValidateToken so SEP-414 spans emitted from signature verification
// nest under the resource server's incoming trace.
func (m *APIMiddleware) validateJWT(ctx context.Context, tokenString string) (userID string, scopes []string, authType string, customClaims map[string]any, err error) {
	if v := m.getValidator(); v != nil {
		resp, verr := v.ValidateToken(ctx, &ValidateTokenRequest{Token: tokenString})
		if verr != nil {
			return "", nil, "", nil, verr
		}
		info := resp.Info
		customClaims = info.CustomClaims
		if customClaims == nil {
			customClaims = make(map[string]any)
		}
		// Store authorization_details in customClaims for context extraction
		if len(info.AuthorizationDetails) > 0 {
			customClaims["__authz_details"] = info.AuthorizationDetails
		}
		return info.Subject, info.Scopes, info.AuthType, customClaims, nil
	}

	// Fallback: single-tenant JWTSecretKey validation (no KeyStore configured)
	return m.validateJWTInline(tokenString)
}

// validateJWTInline is the original inline JWT validation logic, preserved
// as fallback. Will be removed in Phase 3.
func (m *APIMiddleware) validateJWTInline(tokenString string) (userID string, scopes []string, authType string, customClaims map[string]any, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if m.KeyStore != nil {
			// Try kid-based lookup first (if kid header present)
			if kid, ok := token.Header["kid"].(string); ok && kid != "" {
				kidResp, err := m.KeyStore.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: kid})
				if err == nil {
					rec := kidResp.Record
					if token.Header["alg"] != rec.Algorithm {
						return nil, fmt.Errorf("algorithm mismatch: expected %s, got %v", rec.Algorithm, token.Header["alg"])
					}
					// Cross-check: kid's owning client must match the client_id claim
					// to prevent cross-app token forgery (app A signing with client_id=B).
					// Skipped when ClientID is empty (e.g., JWKSKeyStore which doesn't
					// carry client_id metadata).
					if rec.ClientID != "" {
						if claims, ok := token.Claims.(jwt.MapClaims); ok {
							if claimClientID, _ := claims["client_id"].(string); claimClientID != "" && claimClientID != rec.ClientID {
								return nil, fmt.Errorf("kid owner %q does not match client_id claim %q", rec.ClientID, claimClientID)
							}
						}
					}
					return utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
				}
				// kid not found — fall through to client_id lookup
			}

			// Fallback: client_id claim lookup (legacy tokens without kid)
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return nil, fmt.Errorf("invalid claims")
			}
			clientID, _ := claims["client_id"].(string)
			if clientID == "" {
				return nil, fmt.Errorf("missing client_id claim")
			}

			getResp, err := m.KeyStore.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID})
			if err != nil {
				return nil, fmt.Errorf("unknown client: %w", err)
			}
			rec := getResp.Record
			if token.Header["alg"] != rec.Algorithm {
				return nil, fmt.Errorf("algorithm mismatch: expected %s, got %v", rec.Algorithm, token.Header["alg"])
			}
			return utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
		}

		// Fallback: single-key validation (backwards-compatible)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.JWTSecretKey), nil
	})

	if err != nil {
		return "", nil, "", nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return "", nil, "", nil, fmt.Errorf("token validation failed")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, "", nil, fmt.Errorf("invalid claims")
	}

	// Verify token type: reject if explicitly set to something other than "access"
	// (prevents OneAuth refresh tokens from being used as access tokens).
	// External IdP tokens (Keycloak, Auth0) don't include this claim — accepted.
	if tokenType, ok := claims["type"].(string); ok && tokenType != "access" {
		return "", nil, "", nil, fmt.Errorf("invalid token type")
	}

	// Verify issuer if configured
	if m.JWTIssuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != m.JWTIssuer {
			return "", nil, "", nil, fmt.Errorf("invalid issuer")
		}
	}

	// Verify audience if configured (RFC 7519 §4.1.3)
	// Handles both string and array aud claims (#52)
	if m.JWTAudience != "" {
		if !matchesAudience(claims, m.JWTAudience) {
			return "", nil, "", nil, fmt.Errorf("invalid audience")
		}
	}

	// Extract user ID
	userID, ok = claims["sub"].(string)
	if !ok || userID == "" {
		return "", nil, "", nil, fmt.Errorf("missing subject")
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

	// Extract custom claims (everything that's not a standard JWT claim)
	customClaims = make(map[string]any)
	for k, v := range claims {
		if !standardClaims[k] {
			customClaims[k] = v
		}
	}

	// Extract authorization_details (RFC 9396) from JWT claims.
	// Stored under a private key in customClaims so context-setting code can extract it.
	if adRaw, ok := claims["authorization_details"].([]any); ok {
		authzDetails := parseAuthorizationDetailsFromClaims(adRaw)
		if len(authzDetails) > 0 {
			customClaims["__authz_details"] = authzDetails
		}
	}

	// Check blacklist if configured
	if m.Blacklist != nil {
		if jti, ok := claims["jti"].(string); ok && jti != "" {
			if m.Blacklist.IsRevoked(jti) {
				return "", nil, "", nil, fmt.Errorf("token has been revoked")
			}
		}
	}

	return userID, scopes, "jwt", customClaims, nil
}

// validateAPIKey validates an API key
func (m *APIMiddleware) validateAPIKey(ctx context.Context, fullKey string) (userID string, scopes []string, authType string, err error) {
	validateResp, err := m.APIKeyStore.ValidateAPIKey(ctx, &core.ValidateAPIKeyRequest{FullKey: fullKey})
	if err != nil {
		return "", nil, "", fmt.Errorf("invalid API key: %w", err)
	}
	apiKey := validateResp.APIKey

	// Update last used timestamp (best effort, don't fail on error)
	go func() {
		if _, err := m.APIKeyStore.UpdateAPIKeyLastUsed(context.Background(), &core.UpdateAPIKeyLastUsedRequest{KeyID: apiKey.KeyID}); err != nil {
			log.Printf("Failed to update API key last used: %v", err)
		}
	}()

	return apiKey.Subject, apiKey.Scopes, "api_key", nil
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

// =============================================================================
// RFC 9396 helpers
// =============================================================================

// standardADFields are the RFC 9396 §2 common field names used when parsing
// authorization_details from JWT claims to separate known fields from extensions.
var standardADFields = map[string]bool{
	"type": true, "locations": true, "actions": true,
	"datatypes": true, "identifier": true, "privileges": true,
}

// parseAuthorizationDetailsFromClaims converts raw JWT claim data ([]any of
// map[string]any) into typed AuthorizationDetail structs.
func parseAuthorizationDetailsFromClaims(raw []any) []core.AuthorizationDetail {
	var result []core.AuthorizationDetail
	for _, item := range raw {
		adMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ad := core.AuthorizationDetail{
			Type:       stringFromMap(adMap, "type"),
			Identifier: stringFromMap(adMap, "identifier"),
			Locations:  toStringSlice(anySliceFromMap(adMap, "locations")),
			Actions:    toStringSlice(anySliceFromMap(adMap, "actions")),
			DataTypes:  toStringSlice(anySliceFromMap(adMap, "datatypes")),
			Privileges: toStringSlice(anySliceFromMap(adMap, "privileges")),
		}
		for k, v := range adMap {
			if !standardADFields[k] {
				if ad.Extra == nil {
					ad.Extra = make(map[string]any)
				}
				ad.Extra[k] = v
			}
		}
		result = append(result, ad)
	}
	return result
}

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func anySliceFromMap(m map[string]any, key string) []any {
	if v, ok := m[key].([]any); ok {
		return v
	}
	return nil
}

func toStringSlice(raw []any) []string {
	if len(raw) == 0 {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// setAuthContext sets all standard auth context values on the request context.
func setAuthContext(ctx context.Context, userID string, scopes []string, authType string, customClaims map[string]any) context.Context {
	ctx = context.WithValue(ctx, contextKeySubject, userID)
	ctx = context.WithValue(ctx, contextKeyScopes, scopes)
	ctx = context.WithValue(ctx, contextKeyAuthType, authType)
	if customClaims != nil {
		// Extract authorization_details from the private key and set in dedicated context
		if authzDetails, ok := customClaims["__authz_details"].([]core.AuthorizationDetail); ok {
			ctx = context.WithValue(ctx, contextKeyAuthorizationDetails, authzDetails)
			delete(customClaims, "__authz_details")
		}
		ctx = context.WithValue(ctx, contextKeyCustomClaims, customClaims)
	}
	ctx = core.SetSubjectInContext(ctx, userID)
	return ctx
}

// RequireAuthorizationDetails middleware ensures the token contains
// authorization_details matching all required types. For each required type,
// there must be at least one authorization_details entry with that type.
//
// See: https://www.rfc-editor.org/rfc/rfc9396
func (m *APIMiddleware) RequireAuthorizationDetails(requiredTypes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, scopes, authType, customClaims, err := m.validateRequest(r)
			if err != nil {
				m.handleAuthError(w, r, err)
				return
			}

			ctx := setAuthContext(r.Context(), userID, scopes, authType, customClaims)
			granted := GetAuthorizationDetailsFromContext(ctx)

			// Check that all required types are present
			grantedTypes := make(map[string]bool)
			for _, ad := range granted {
				grantedTypes[ad.Type] = true
			}
			for _, reqType := range requiredTypes {
				if !grantedTypes[reqType] {
					m.handleAuthError(w, r, fmt.Errorf("missing required authorization_details type: %s", reqType))
					return
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
