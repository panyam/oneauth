package apiauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// standardClaims is the set of JWT claim keys that cannot be
// overridden by CustomClaimsFunc — the token issuer rejects custom
// values for these names.
var standardClaims = map[string]bool{
	"sub": true, "iss": true, "aud": true, "exp": true,
	"iat": true, "type": true, "scopes": true, "jti": true,
	"authorization_details": true, // RFC 9396
}

// Context keys for API authentication. Unexported so callers go
// through the typed Get*FromAPIContext accessors below.
type apiContextKey string

const (
	contextKeySubject              apiContextKey = "api_user_id"
	contextKeyScopes               apiContextKey = "api_scopes"
	contextKeyAuthType             apiContextKey = "api_auth_type" // "jwt" or "api_key"
	contextKeyCustomClaims         apiContextKey = "api_custom_claims"
	contextKeyAuthorizationDetails apiContextKey = "api_authorization_details" // RFC 9396
)

// APIMiddleware validates Bearer tokens (JWT or API key) and exposes
// the validated subject + scopes + claims on the request context for
// downstream handlers.
//
// Wire one of:
//
//   - Validator (preferred) — the new gRPC-shape TokenValidator. Cleanest
//     path; KeyStore/JWTSecretKey become opt-in fallbacks.
//   - KeyStore — multi-tenant JWT validation via GetKeyByKid / GetKey.
//     A jwtValidator is lazily built on first use.
//   - JWTSecretKey — single-tenant fallback (HS256). Inline validation.
//
// Optional add-ons: APIKeyStore (for "oa_..." API keys), Introspection
// (RFC 7662 fallback when local validation fails), Blacklist
// (jti-based revocation).
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

	// LegacyQueryParamBearer is the query parameter name to check for a
	// bearer token when the Authorization header is missing (e.g., "token"
	// for ?token=...). Empty disables the path (default).
	//
	// OAuth 2.1 §5.4 retired query-param bearer carry; RFC 6750 §2.3 had
	// deprecated it in 2012. Query-carried tokens leak into browser
	// history, access logs, Referer headers, and caches. The path is
	// retained for OAuth 2.0 deployments that genuinely cannot move the
	// token to the Authorization header (the WebSocket upgrade case is
	// the typical one — see docs/DEMOS.md for the three alternatives).
	// Operators take responsibility for the leak surface; a one-time
	// warning logs at first use.
	//
	// Tracked under capability-gating umbrella #344.
	LegacyQueryParamBearer string

	// legacyQueryParamBearerWarning fires once per APIMiddleware instance
	// the first time the query-param fallback path actually executes.
	legacyQueryParamBearerWarning sync.Once

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

// GetScopesFromAPIContext retrieves the granted scopes from the API middleware context.
func GetScopesFromAPIContext(ctx context.Context) []string {
	if v := ctx.Value(contextKeyScopes); v != nil {
		if scopes, ok := v.([]string); ok {
			return scopes
		}
	}
	return nil
}

// GetAuthTypeFromAPIContext retrieves the auth type ("jwt" or "api_key") from context.
func GetAuthTypeFromAPIContext(ctx context.Context) string {
	if v := ctx.Value(contextKeyAuthType); v != nil {
		if authType, ok := v.(string); ok {
			return authType
		}
	}
	return ""
}

// GetCustomClaimsFromContext retrieves the custom (non-standard) JWT
// claims from context. Returns nil if no custom claims are present.
func GetCustomClaimsFromContext(ctx context.Context) map[string]any {
	if v := ctx.Value(contextKeyCustomClaims); v != nil {
		if claims, ok := v.(map[string]any); ok {
			return claims
		}
	}
	return nil
}

// GetAuthorizationDetailsFromContext retrieves the RFC 9396
// authorization_details from context. Returns nil if no details are
// present (e.g., API key auth or token without RAR).
func GetAuthorizationDetailsFromContext(ctx context.Context) []core.AuthorizationDetail {
	if v := ctx.Value(contextKeyAuthorizationDetails); v != nil {
		if details, ok := v.([]core.AuthorizationDetail); ok {
			return details
		}
	}
	return nil
}

// ValidateToken validates Bearer tokens (JWT or API key) and sets
// user info in the request context for downstream handlers.
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

// RequireScopes ensures the authenticated user has all required scopes.
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

// Optional allows requests without auth but sets user info when present.
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

// RequireAuthorizationDetails ensures the token carries
// authorization_details matching all required types. For each
// required type there must be at least one entry with that type.
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

func (m *APIMiddleware) validateRequest(r *http.Request) (userID string, scopes []string, authType string, customClaims map[string]any, err error) {
	header := m.AuthHeader
	if header == "" {
		header = "Authorization"
	}

	authHeader := r.Header.Get(header)

	if authHeader == "" && m.LegacyQueryParamBearer != "" {
		if qp := r.URL.Query().Get(m.LegacyQueryParamBearer); qp != "" {
			m.legacyQueryParamBearerWarning.Do(func() {
				log.Printf("apiauth.APIMiddleware: LEGACY OAuth 2.0 PATH — bearer token received via query parameter %q. "+
					"OAuth 2.1 §5.4 retired this carry; URL query params leak tokens into browser history, "+
					"access logs, Referer headers, and caches. For WebSocket upgrade flows see docs/DEMOS.md "+
					"for three alternatives (subprotocol header, initial-frame auth, short-lived ticket). "+
					"Disable by leaving APIMiddleware.LegacyQueryParamBearer empty.", m.LegacyQueryParamBearer)
			})
			authHeader = "Bearer " + qp
		}
	}

	if authHeader == "" {
		return "", nil, "", nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", nil, "", nil, fmt.Errorf("invalid authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", nil, "", nil, fmt.Errorf("empty token")
	}

	// API key path (token prefix matches the API-key issuer).
	if strings.HasPrefix(token, "oa_") && m.APIKeyStore != nil {
		userID, scopes, authType, err := m.validateAPIKey(r.Context(), token)
		return userID, scopes, authType, nil, err
	}

	// Local JWT validation.
	userID, scopes, authType, customClaims, jwtErr := m.validateJWT(r.Context(), token)
	if jwtErr == nil {
		return userID, scopes, authType, customClaims, nil
	}

	// Introspection fallback when configured.
	if m.Introspection != nil {
		return m.Introspection.ValidateForMiddlewareWithContext(r.Context(), token)
	}

	return "", nil, "", nil, jwtErr
}

func (m *APIMiddleware) getValidator() TokenValidator {
	if m.Validator != nil {
		return m.Validator
	}
	m.validatorOnce.Do(func() {
		if m.KeyStore != nil {
			m.lazyValidator = NewJWTValidator(JWTValidatorConfig{
				KeyLookup:      m.KeyStore,
				Blacklist:      m.Blacklist,
				Issuer:         m.JWTIssuer,
				Audience:       m.JWTAudience,
				TracerProvider: m.TracerProvider,
			})
		} else {
			m.lazyValidator = nil
		}
	})
	return m.lazyValidator
}

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
		if len(info.AuthorizationDetails) > 0 {
			customClaims["__authz_details"] = info.AuthorizationDetails
		}
		return info.Subject, info.Scopes, info.AuthType, customClaims, nil
	}

	return m.validateJWTInline(tokenString)
}

func (m *APIMiddleware) validateJWTInline(tokenString string) (userID string, scopes []string, authType string, customClaims map[string]any, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if m.KeyStore != nil {
			if kid, ok := token.Header["kid"].(string); ok && kid != "" {
				kidResp, err := m.KeyStore.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: kid})
				if err == nil {
					rec := kidResp.Record
					if token.Header["alg"] != rec.Algorithm {
						return nil, fmt.Errorf("algorithm mismatch: expected %s, got %v", rec.Algorithm, token.Header["alg"])
					}
					if rec.ClientID != "" {
						if claims, ok := token.Claims.(jwt.MapClaims); ok {
							if claimClientID, _ := claims["client_id"].(string); claimClientID != "" && claimClientID != rec.ClientID {
								return nil, fmt.Errorf("kid owner %q does not match client_id claim %q", rec.ClientID, claimClientID)
							}
						}
					}
					return utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
				}
			}

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

	if tokenType, ok := claims["type"].(string); ok && tokenType != "access" {
		return "", nil, "", nil, fmt.Errorf("invalid token type")
	}

	if m.JWTIssuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != m.JWTIssuer {
			return "", nil, "", nil, fmt.Errorf("invalid issuer")
		}
	}

	if m.JWTAudience != "" {
		if !matchesAudience(claims, m.JWTAudience) {
			return "", nil, "", nil, fmt.Errorf("invalid audience")
		}
	}

	userID, ok = claims["sub"].(string)
	if !ok || userID == "" {
		return "", nil, "", nil, fmt.Errorf("missing subject")
	}

	if scopesRaw, ok := claims["scopes"].([]any); ok {
		scopes = make([]string, 0, len(scopesRaw))
		for _, s := range scopesRaw {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	customClaims = make(map[string]any)
	for k, v := range claims {
		if !standardClaims[k] {
			customClaims[k] = v
		}
	}

	if adRaw, ok := claims["authorization_details"].([]any); ok {
		authzDetails := parseAuthorizationDetailsFromClaims(adRaw)
		if len(authzDetails) > 0 {
			customClaims["__authz_details"] = authzDetails
		}
	}

	if m.Blacklist != nil {
		if jti, ok := claims["jti"].(string); ok && jti != "" {
			if m.Blacklist.IsRevoked(jti) {
				return "", nil, "", nil, fmt.Errorf("token has been revoked")
			}
		}
	}

	return userID, scopes, "jwt", customClaims, nil
}

func (m *APIMiddleware) validateAPIKey(ctx context.Context, fullKey string) (userID string, scopes []string, authType string, err error) {
	validateResp, err := m.APIKeyStore.ValidateAPIKey(ctx, &core.ValidateAPIKeyRequest{FullKey: fullKey})
	if err != nil {
		return "", nil, "", fmt.Errorf("invalid API key: %w", err)
	}
	apiKey := validateResp.APIKey

	go func() {
		if _, err := m.APIKeyStore.UpdateAPIKeyLastUsed(context.Background(), &core.UpdateAPIKeyLastUsedRequest{KeyID: apiKey.KeyID}); err != nil {
			log.Printf("Failed to update API key last used: %v", err)
		}
	}()

	return apiKey.Subject, apiKey.Scopes, "api_key", nil
}

func (m *APIMiddleware) handleAuthError(w http.ResponseWriter, r *http.Request, err error) {
	if m.OnAuthError != nil {
		m.OnAuthError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": err.Error(),
	})
}

// setAuthContext sets all standard auth context values on the request context.
func setAuthContext(ctx context.Context, userID string, scopes []string, authType string, customClaims map[string]any) context.Context {
	ctx = context.WithValue(ctx, contextKeySubject, userID)
	ctx = context.WithValue(ctx, contextKeyScopes, scopes)
	ctx = context.WithValue(ctx, contextKeyAuthType, authType)
	if customClaims != nil {
		if authzDetails, ok := customClaims["__authz_details"].([]core.AuthorizationDetail); ok {
			ctx = context.WithValue(ctx, contextKeyAuthorizationDetails, authzDetails)
			delete(customClaims, "__authz_details")
		}
		ctx = context.WithValue(ctx, contextKeyCustomClaims, customClaims)
	}
	ctx = core.SetSubjectInContext(ctx, userID)
	return ctx
}

// getClientIP extracts the client IP from the request — used by the
// token endpoint for rate-limiting keys.
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return ip
}
