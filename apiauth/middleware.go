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
	"cnf":                   true, // RFC 7800 / RFC 9449 — sender-constraint, never caller-supplied
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

	// DPoP, when non-nil, opts this resource server into RFC 9449
	// sender-constrained tokens: it accepts `Authorization: DPoP <token>`
	// with a proof over the request, checks the proof's `ath` and its key
	// against the token's `cnf.jkt`, and refuses a bound token presented
	// under the Bearer scheme (§7.2 downgrade).
	//
	// Nil keeps the middleware bearer-only, in which case a bound token is
	// accepted as an ordinary bearer token — which is what RFC 9449 §7.2
	// says a DPoP-unaware resource server will do, and why a deployment
	// that issues bound tokens should wire this everywhere before relying
	// on the binding.
	//
	// Build one with NewDPoPProofValidator, setting DPoPConfig.BaseURL to
	// this resource server's externally-visible scheme and host.
	DPoP *DPoPProofValidator

	// RequireDPoP refuses any token presented under the Bearer scheme, so
	// every request must carry a DPoP-bound token and a proof. It is the
	// enforcement behind RFC 9728's dpop_bound_access_tokens_required, and
	// the two are set together: advertising the requirement without
	// enforcing it tells clients they are protected by a check that does
	// not run.
	//
	// Ignored when DPoP is nil, since a middleware with no validator cannot
	// check a proof and would reject every request.
	RequireDPoP bool

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
		info, err := m.validateRequest(r)
		if err != nil {
			m.handleAuthError(w, r, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(setAuthContext(r.Context(), info)))
	})
}

// RequireScopes ensures the authenticated user has all required scopes.
func (m *APIMiddleware) RequireScopes(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, err := m.validateRequest(r)
			if err != nil {
				m.handleAuthError(w, r, err)
				return
			}

			if !core.ContainsAllScopes(info.Scopes, requiredScopes) {
				m.handleAuthError(w, r, fmt.Errorf("insufficient scope: requires %v", requiredScopes))
				return
			}

			next.ServeHTTP(w, r.WithContext(setAuthContext(r.Context(), info)))
		})
	}
}

// Optional allows requests without auth but sets user info when present.
func (m *APIMiddleware) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, err := m.validateRequest(r)
		if err == nil && info.Subject != "" {
			r = r.WithContext(setAuthContext(r.Context(), info))
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
			info, err := m.validateRequest(r)
			if err != nil {
				m.handleAuthError(w, r, err)
				return
			}

			ctx := setAuthContext(r.Context(), info)
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

// validateRequest authenticates one inbound request and returns what the
// token says about its bearer.
//
// Beyond validating the token, it enforces the RFC 9449 §7 rules that decide
// whether this presentation of the token is legitimate:
//
//   - a token presented under the DPoP scheme must come with a proof whose
//     key matches the token's `cnf.jkt`
//   - a token carrying `cnf` must NOT be accepted under the Bearer scheme,
//     which is the downgrade §7.2 closes; without this check a thief simply
//     drops the DPoP header and the binding buys nothing
//
// Failures return *authError so the caller can emit the right
// WWW-Authenticate challenge.
func (m *APIMiddleware) validateRequest(r *http.Request) (*TokenInfo, error) {
	scheme, token, err := m.credentials(r)
	if err != nil {
		return nil, err
	}

	if scheme == TokenTypeDPoP && m.DPoP == nil {
		return nil, &authError{
			Scheme:      TokenTypeBearer,
			Code:        "invalid_request",
			Description: "this resource server does not support the DPoP scheme",
		}
	}

	info, err := m.authenticate(r, scheme, token)
	if err != nil {
		return nil, err
	}

	if err := m.enforceBinding(r, scheme, token, info); err != nil {
		return nil, err
	}
	return info, nil
}

// credentials pulls the authentication scheme and token out of the request.
// The scheme is normalized to TokenTypeBearer or TokenTypeDPoP; anything else
// is refused, since accepting an unknown scheme would mean guessing which
// rules apply to it.
func (m *APIMiddleware) credentials(r *http.Request) (scheme, token string, err error) {
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
		// No credentials at all: the challenge carries no error code, per
		// RFC 6750 §3.1 and RFC 9449 §7.2.
		return "", "", &authError{err: fmt.Errorf("missing authorization header")}
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return "", "", &authError{Code: "invalid_request", Description: "malformed authorization header"}
	}

	switch {
	case strings.EqualFold(parts[0], TokenTypeBearer):
		scheme = TokenTypeBearer
	case strings.EqualFold(parts[0], TokenTypeDPoP):
		scheme = TokenTypeDPoP
	default:
		return "", "", &authError{Code: "invalid_request", Description: "unsupported authorization scheme"}
	}

	token = strings.TrimSpace(parts[1])
	if token == "" {
		return "", "", &authError{Scheme: scheme, Code: "invalid_token", Description: "empty token"}
	}
	return scheme, token, nil
}

// authenticate resolves the token to a TokenInfo via the API-key store, local
// JWT validation, or remote introspection, in that order.
//
// An API key under the DPoP scheme is refused rather than silently accepted:
// API keys carry no `cnf`, so there is nothing for a proof to be checked
// against, and honoring the request would tell the client it holds a
// sender-constrained credential when it does not.
func (m *APIMiddleware) authenticate(r *http.Request, scheme, token string) (*TokenInfo, error) {
	if strings.HasPrefix(token, "oa_") && m.APIKeyStore != nil {
		if scheme == TokenTypeDPoP {
			return nil, &authError{
				Scheme:      TokenTypeDPoP,
				Code:        "invalid_token",
				Description: "API keys cannot be presented under the DPoP scheme",
			}
		}
		info, err := m.validateAPIKey(r.Context(), token)
		if err != nil {
			return nil, &authError{Scheme: scheme, Code: "invalid_token", err: err}
		}
		return info, nil
	}

	info, jwtErr := m.validateJWT(r.Context(), token)
	if jwtErr == nil {
		return info, nil
	}

	if m.Introspection != nil {
		info, introspectErr := m.Introspection.ValidateInfo(r.Context(), token)
		if introspectErr != nil {
			return nil, &authError{Scheme: scheme, Code: "invalid_token", err: introspectErr}
		}
		return info, nil
	}

	return nil, &authError{Scheme: scheme, Code: "invalid_token", err: jwtErr}
}

// enforceBinding applies RFC 9449 §7 once the token itself is known good.
//
// The unbound-token-under-DPoP case is not settled by the RFC. This
// implementation refuses it: the client asked for its request to be judged on
// a key binding, and the token has none, so honoring the request would leave
// the client believing it has protection that does not exist. Failing here
// surfaces the misconfiguration at the first request instead of at the first
// token theft.
func (m *APIMiddleware) enforceBinding(r *http.Request, scheme, token string, info *TokenInfo) error {
	if m.DPoP == nil {
		return nil
	}

	if scheme == TokenTypeBearer {
		if m.RequireDPoP {
			return &authError{
				Scheme:      TokenTypeDPoP,
				Code:        "invalid_token",
				Description: "this resource requires a DPoP-bound access token",
			}
		}
		if !info.Confirmation.IsEmpty() {
			return &authError{
				Scheme:      TokenTypeDPoP,
				Code:        "invalid_token",
				Description: "DPoP-bound token presented as a bearer token",
			}
		}
		return nil
	}

	proven, err := m.DPoP.ConfirmResource(r.Context(), r, token)
	if err != nil {
		// §9 mirrors §8 at the resource server: the challenge rides a
		// 401 with the DPoP scheme, and carries the nonce to use next.
		var nonceErr *NonceRequiredError
		if errors.As(err, &nonceErr) {
			return &authError{
				Scheme:      TokenTypeDPoP,
				Code:        ErrorUseDPoPNonce,
				Description: nonceErr.Error(),
				nonce:       nonceErr.Nonce,
			}
		}
		ge, _ := asGrantError(err)
		description := "invalid DPoP proof"
		if ge != nil {
			description = ge.Description
		}
		return &authError{Scheme: TokenTypeDPoP, Code: "invalid_dpop_proof", Description: description}
	}

	if info.Confirmation.IsEmpty() {
		return &authError{
			Scheme:      TokenTypeDPoP,
			Code:        "invalid_token",
			Description: "token is not bound to a DPoP key",
		}
	}
	if !info.Confirmation.Equal(proven) {
		return &authError{
			Scheme:      TokenTypeDPoP,
			Code:        "invalid_token",
			Description: "Invalid DPoP key binding",
		}
	}
	return nil
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

func (m *APIMiddleware) validateJWT(ctx context.Context, tokenString string) (*TokenInfo, error) {
	if v := m.getValidator(); v != nil {
		resp, verr := v.ValidateToken(ctx, &ValidateTokenRequest{Token: tokenString})
		if verr != nil {
			return nil, verr
		}
		info := resp.Info
		if info.CustomClaims == nil {
			info.CustomClaims = make(map[string]any)
		}
		return info, nil
	}

	return m.validateJWTInline(tokenString)
}

func (m *APIMiddleware) validateJWTInline(tokenString string) (*TokenInfo, error) {
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
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token validation failed")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	if tokenType, ok := claims["type"].(string); ok && tokenType != "access" {
		return nil, fmt.Errorf("invalid token type")
	}

	if m.JWTIssuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != m.JWTIssuer {
			return nil, fmt.Errorf("invalid issuer")
		}
	}

	if m.JWTAudience != "" {
		if !matchesAudience(claims, m.JWTAudience) {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	userID, _ := claims["sub"].(string)
	if userID == "" {
		return nil, fmt.Errorf("missing subject")
	}

	var scopes []string
	if scopesRaw, ok := claims["scopes"].([]any); ok {
		scopes = make([]string, 0, len(scopesRaw))
		for _, s := range scopesRaw {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	customClaims := make(map[string]any)
	for k, v := range claims {
		if !standardClaims[k] {
			customClaims[k] = v
		}
	}

	var authzDetails []core.AuthorizationDetail
	if adRaw, ok := claims["authorization_details"].([]any); ok {
		authzDetails = parseAuthorizationDetailsFromClaims(adRaw)
	}

	if m.Blacklist != nil {
		if jti, ok := claims["jti"].(string); ok && jti != "" {
			if m.Blacklist.IsRevoked(jti) {
				return nil, fmt.Errorf("token has been revoked")
			}
		}
	}

	return &TokenInfo{
		Subject:              userID,
		Scopes:               scopes,
		AuthorizationDetails: authzDetails,
		CustomClaims:         customClaims,
		AuthType:             "jwt",
		Confirmation:         confirmationFromClaims(claims),
	}, nil
}

func (m *APIMiddleware) validateAPIKey(ctx context.Context, fullKey string) (*TokenInfo, error) {
	validateResp, err := m.APIKeyStore.ValidateAPIKey(ctx, &core.ValidateAPIKeyRequest{FullKey: fullKey})
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}
	apiKey := validateResp.APIKey

	go func() {
		if _, err := m.APIKeyStore.UpdateAPIKeyLastUsed(context.Background(), &core.UpdateAPIKeyLastUsedRequest{KeyID: apiKey.KeyID}); err != nil {
			log.Printf("Failed to update API key last used: %v", err)
		}
	}()

	return &TokenInfo{Subject: apiKey.Subject, Scopes: apiKey.Scopes, AuthType: "api_key"}, nil
}

// authError is a failed authentication plus the WWW-Authenticate challenge it
// should produce. Scheme names which authentication scheme the challenge
// carries error information for, and is empty when the request presented no
// credentials at all, since RFC 6750 §3.1 says a challenge to a request that
// tried nothing must not report an error.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.1
type authError struct {
	Scheme      string
	Code        string
	Description string

	// nonce, when set, is handed back in the DPoP-Nonce header so the
	// client can retry immediately (RFC 9449 §9).
	nonce string

	err error
}

// Error renders the message callers see in logs and in the JSON body. The
// wrapped error is preferred when present because it carries the specific
// validation failure; Description is the client-facing summary.
func (e *authError) Error() string {
	switch {
	case e.err != nil:
		return e.err.Error()
	case e.Description != "":
		return e.Description
	default:
		return "unauthorized"
	}
}

func (e *authError) Unwrap() error { return e.err }

func (m *APIMiddleware) handleAuthError(w http.ResponseWriter, r *http.Request, err error) {
	if m.OnAuthError != nil {
		m.OnAuthError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", m.challenge(err))
	var nonceErr *authError
	if errors.As(err, &nonceErr) && nonceErr.nonce != "" {
		w.Header().Set(DPoPNonceHeader, nonceErr.nonce)
	}
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": err.Error(),
	})
}

// challenge builds the WWW-Authenticate value for a failed request.
//
// A bearer-only resource server keeps emitting exactly `Bearer realm="api"`,
// whatever went wrong. Once DPoP is wired, the response advertises both
// schemes, and error information rides on the scheme the client actually
// used — a client that sent a bad proof needs to see `invalid_dpop_proof`
// against DPoP, not a generic bearer challenge it cannot act on.
//
// Parameters within a challenge are comma-separated per RFC 9110 §11.6.1,
// which is also how RFC 9449 Figure 16 writes them.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.2
func (m *APIMiddleware) challenge(err error) string {
	const bearerChallenge = `Bearer realm="api"`
	if m.DPoP == nil {
		return bearerChallenge
	}
	algs := `algs="` + strings.Join(m.DPoP.SigningAlgValuesSupported(), " ") + `"`

	var ae *authError
	if !errors.As(err, &ae) || ae.Scheme == "" {
		// Nothing was attempted, or the scheme could not be established:
		// advertise both, report nothing (RFC 6750 §3.1).
		return bearerChallenge + ", DPoP " + algs
	}

	var params []string
	if ae.Code != "" {
		params = append(params, `error="`+ae.Code+`"`)
		if ae.Description != "" {
			params = append(params, `error_description="`+sanitizeChallengeValue(ae.Description)+`"`)
		}
	}

	if ae.Scheme == TokenTypeDPoP {
		return bearerChallenge + ", DPoP " + strings.Join(append(params, algs), ", ")
	}
	return strings.Join(append([]string{bearerChallenge}, params...), ", ") + ", DPoP " + algs
}

// sanitizeChallengeValue strips the characters that would break out of the
// quoted-string a challenge parameter lives in. Descriptions are built from
// validation failures, and one carrying a stray quote would corrupt the whole
// header rather than just its own parameter.
func sanitizeChallengeValue(v string) string {
	return strings.NewReplacer(`"`, "'", "\\", "/", "\r", " ", "\n", " ").Replace(v)
}

// setAuthContext sets all standard auth context values on the request context.
func setAuthContext(ctx context.Context, info *TokenInfo) context.Context {
	if info == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, contextKeySubject, info.Subject)
	ctx = context.WithValue(ctx, contextKeyScopes, info.Scopes)
	ctx = context.WithValue(ctx, contextKeyAuthType, info.AuthType)
	if len(info.AuthorizationDetails) > 0 {
		ctx = context.WithValue(ctx, contextKeyAuthorizationDetails, info.AuthorizationDetails)
	}
	if info.CustomClaims != nil {
		ctx = context.WithValue(ctx, contextKeyCustomClaims, info.CustomClaims)
	}
	ctx = core.SetSubjectInContext(ctx, info.Subject)
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
