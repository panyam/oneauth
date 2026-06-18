package apiauth

import (
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

	// AuthorizationCodeStore enables the RFC 6749 §4.1 authorization-
	// code grant. When non-nil the token endpoint accepts
	// grant_type=authorization_code and the caller is expected to
	// mount AuthorizationHandler / AuthorizeVerificationHandler at the
	// /authorize path (typically via MountAuthorize). Nil keeps the
	// token endpoint behaviorally identical to its pre-#297 surface.
	AuthorizationCodeStore core.AuthorizationCodeStore

	// AppStore lets the token endpoint look up a registered client's
	// `token_endpoint_auth_method` to decide whether confidential-client
	// authentication is required on the device-code redemption path
	// (issue 266).
	//
	// When nil, the device-grant handler accepts the form `client_id`
	// alone for backward compatibility with the v0.1.23 wire protocol.
	//
	// When non-nil, AppStore becomes the source of truth: the device
	// authorization's bound client_id MUST resolve to a registered
	// AppRegistration, otherwise the redemption is rejected with
	// `invalid_client`. The handler does NOT silently downgrade to the
	// unauthenticated path on lookup failure — opting into AppStore is
	// opting into strict enforcement. Production deployments with
	// confidential device clients MUST wire it so a stolen device_code
	// cannot be redeemed without the registered client's credentials.
	AppStore core.AppRegistrationStore

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
			// RFC 6749 §4.1.3 — authorization-code grant inputs.
			Code:         r.FormValue("code"),
			CodeVerifier: r.FormValue("code_verifier"),
			RedirectURI:  r.FormValue("redirect_uri"),
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
	case AuthorizationCodeGrantType:
		a.handleAuthorizationCodeGrant(w, r, &req)
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

