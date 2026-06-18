package apiauth

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/tracing"
)

// TokenEndpointHandler serves POST /api/token (RFC 6749 §3.2). It is
// a peer to IntrospectionHandler and RevocationHandler — a thin HTTP
// shim over the gRPC-shape interfaces on OneAuth (TokenIssuer for
// password/refresh/client_credentials, AuthorizationCodeGranter,
// DeviceCodeGranter, JwtBearerGranter, TokenExchanger).
//
// HTTP-side concerns the granters do not own — form parsing, rate
// limiting, refresh-token creation with device info, AuthHooks
// firing, tracing — live here. Logic-side concerns are entirely
// delegated.
type TokenEndpointHandler struct {
	// OneAuth provides the granters and shared state. Required.
	OneAuth *OneAuth

	// RateLimiter throttles password-grant attempts by client IP +
	// username. Nil disables rate limiting.
	RateLimiter core.RateLimiter

	// TracerProvider opts the handler into SEP-414 tracing. Nil keeps
	// the no-op fast path.
	TracerProvider trace.TracerProvider
}

// NewTokenEndpointHandler constructs a handler over the supplied
// OneAuth instance. RateLimiter and TracerProvider are optional.
func NewTokenEndpointHandler(oa *OneAuth) *TokenEndpointHandler {
	return &TokenEndpointHandler{OneAuth: oa}
}

// ServeHTTP routes the token-endpoint request to the granter matching
// the form's grant_type. Supports both application/x-www-form-urlencoded
// (RFC 6749 standard) and application/json request bodies.
func (h *TokenEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracing.Tracer(h.TracerProvider, tracing.InstrumentationName).
		Start(tracing.Extract(r), "oneauth.token.issue", trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	r = r.WithContext(ctx)

	if r.Method != http.MethodPost {
		span.SetStatus(codes.Error, "method not allowed")
		h.writeError(w, &GrantError{Code: "invalid_request", Description: "method not allowed", Status: http.StatusMethodNotAllowed})
		return
	}

	req, err := parseTokenRequest(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	span.SetAttributes(attribute.String("oauth.grant_type", req.GrantType))

	switch req.GrantType {
	case "password":
		h.handlePassword(w, r, req)
	case "refresh_token":
		h.handleRefresh(w, r, req)
	case "client_credentials":
		h.handleClientCredentials(w, r, req)
	case AuthorizationCodeGrantType:
		h.dispatchAuthorizationCode(w, r, req)
	case DeviceCodeGrantType:
		h.dispatchDeviceCode(w, r, req)
	case JwtBearerGrantType:
		h.dispatchJwtBearer(w, r, req)
	case TokenExchangeGrantType:
		h.dispatchTokenExchange(w, r, req)
	default:
		span.SetStatus(codes.Error, "unsupported_grant_type")
		h.writeError(w, unsupportedGrantType("grant_type not supported"))
	}
}

// parseTokenRequest reads the request body and returns the parsed
// core.TokenRequest. Returns a *GrantError on malformed input.
func parseTokenRequest(r *http.Request) (*core.TokenRequest, *GrantError) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			return nil, invalidRequest("invalid form body")
		}
		req := &core.TokenRequest{
			GrantType:           r.FormValue("grant_type"),
			Username:            r.FormValue("username"),
			Password:            r.FormValue("password"),
			RefreshToken:        r.FormValue("refresh_token"),
			Scope:               r.FormValue("scope"),
			ClientID:            r.FormValue("client_id"),
			ClientSecret:        r.FormValue("client_secret"),
			DeviceCode:          r.FormValue("device_code"),
			Code:                r.FormValue("code"),
			CodeVerifier:        r.FormValue("code_verifier"),
			RedirectURI:         r.FormValue("redirect_uri"),
			ClientAssertionType: r.FormValue("client_assertion_type"),
			ClientAssertion:     r.FormValue("client_assertion"),
			Assertion:           r.FormValue("assertion"),
			SubjectToken:        r.FormValue("subject_token"),
			SubjectTokenType:    r.FormValue("subject_token_type"),
			RequestedTokenType:  r.FormValue("requested_token_type"),
			Resource:            r.FormValue("resource"),
			Audience:            r.FormValue("audience"),
		}
		if adStr := r.FormValue("authorization_details"); adStr != "" {
			if err := json.Unmarshal([]byte(adStr), &req.AuthorizationDetails); err != nil {
				return nil, &GrantError{Code: "invalid_authorization_details", Description: "invalid authorization_details JSON", Status: http.StatusBadRequest}
			}
		}
		return req, nil
	}
	var req core.TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, invalidRequest("invalid request body")
	}
	return &req, nil
}

// handlePassword owns the HTTP-side concerns of the password grant —
// rate limiting, refresh-token creation with device info, AuthHooks
// firing — and delegates credential validation + scope intersection +
// access-token mint to OneAuth.Issuer.PasswordGrant.
func (h *TokenEndpointHandler) handlePassword(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if h.OneAuth == nil || h.OneAuth.Issuer == nil {
		h.writeError(w, serverError("token endpoint not configured"))
		return
	}
	if h.RateLimiter != nil {
		key := getClientIP(r) + ":" + req.Username
		if !h.RateLimiter.Allow(key) {
			h.writeError(w, &GrantError{Code: "rate_limit_exceeded", Description: "too many login attempts", Status: http.StatusTooManyRequests})
			return
		}
	}

	resp, err := h.OneAuth.Issuer.PasswordGrant(r.Context(), &PasswordGrantRequest{
		Username:             req.Username,
		Password:             req.Password,
		Scopes:               core.ParseScopes(req.Scope),
		AuthorizationDetails: req.AuthorizationDetails,
		ClientID:             req.ClientID,
	})
	if err != nil {
		// Issuer.PasswordGrant uses an `invalid_grant: ...` prefix for
		// credentials-failed errors and `server_error: ...` for
		// internal failures. AuthHooks fire on the credentials path
		// only.
		msg := err.Error()
		switch {
		case strings.HasPrefix(msg, "invalid_grant"):
			h.fireOnLoginFailure(req.Username, err)
			h.writeError(w, &GrantError{Code: "invalid_grant", Description: "invalid credentials", Status: http.StatusUnauthorized})
		default:
			log.Printf("password grant: %v", err)
			h.writeError(w, serverError("password grant failed"))
		}
		return
	}

	// Refresh token (HTTP-side: device info captured from request).
	var refreshTokenStr string
	if h.OneAuth.RefreshStore != nil {
		deviceInfo := map[string]any{
			"user_agent": r.UserAgent(),
			"ip":         getClientIP(r),
			"created_at": time.Now().UTC().Format(time.RFC3339),
		}
		createResp, rtErr := h.OneAuth.RefreshStore.CreateRefreshToken(r.Context(), &core.CreateRefreshTokenRequest{
			Subject:    resp.Subject,
			ClientID:   req.ClientID,
			DeviceInfo: deviceInfo,
			Scopes:     resp.GrantedScopes,
		})
		if rtErr != nil {
			log.Printf("create refresh token: %v", rtErr)
			h.writeError(w, serverError("failed to create session"))
			return
		}
		refreshTokenStr = createResp.Token.Token
	}

	h.fireOnLoginSuccess(resp.Subject)
	h.writeTokens(w, &core.TokenPair{
		AccessToken:          resp.AccessToken,
		TokenType:            "Bearer",
		ExpiresIn:            resp.ExpiresIn,
		RefreshToken:         refreshTokenStr,
		Scope:                core.JoinScopes(resp.GrantedScopes),
		AuthorizationDetails: resp.AuthorizationDetails,
	})
}

// handleRefresh delegates the full grant flow to TokenIssuer.RefreshGrant.
func (h *TokenEndpointHandler) handleRefresh(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if h.OneAuth == nil || h.OneAuth.Issuer == nil {
		h.writeError(w, serverError("token endpoint not configured"))
		return
	}
	if req.RefreshToken == "" {
		h.writeError(w, invalidRequest("refresh_token is required"))
		return
	}
	resp, err := h.OneAuth.Issuer.RefreshGrant(r.Context(), &RefreshGrantRequest{RefreshToken: req.RefreshToken})
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "invalid_grant"), strings.Contains(msg, "expired"), strings.Contains(msg, "revoked"), strings.Contains(msg, "reuse"):
			h.writeError(w, &GrantError{Code: "invalid_grant", Description: msg, Status: http.StatusUnauthorized})
		default:
			log.Printf("refresh grant: %v", err)
			h.writeError(w, serverError("refresh grant failed"))
		}
		return
	}
	h.writeTokens(w, resp.Tokens)
}

// handleClientCredentials authenticates the client and mints a
// client-scoped access token. Authentication uses the wired
// ClientAuthenticator (private_key_jwt / client_secret_jwt /
// client_secret_basic / client_secret_post); minting goes through
// TokenIssuer.CreateAccessToken with sub=client_id.
//
// We do NOT delegate to TokenIssuer.ClientCredentials because that
// method does its own client-secret check and would reject any
// request authenticated via the assertion path (where ClientSecret
// is empty by construction).
func (h *TokenEndpointHandler) handleClientCredentials(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if h.OneAuth == nil || h.OneAuth.Issuer == nil {
		h.writeError(w, serverError("token endpoint not configured"))
		return
	}

	authedClientID, gErr := h.authenticateClient(r, req)
	if gErr != nil {
		h.writeError(w, gErr)
		return
	}

	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		h.writeError(w, &GrantError{Code: "invalid_authorization_details", Description: err.Error(), Status: http.StatusBadRequest})
		return
	}

	scopes := core.ParseScopes(req.Scope)
	tok, err := h.OneAuth.Issuer.CreateAccessToken(r.Context(), &CreateAccessTokenRequest{
		Subject:              authedClientID,
		Scopes:               scopes,
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		log.Printf("client_credentials mint: %v", err)
		h.writeError(w, serverError("failed to create token"))
		return
	}

	h.writeTokens(w, &core.TokenPair{
		AccessToken:          tok.Token,
		TokenType:            "Bearer",
		ExpiresIn:            tok.ExpiresIn,
		Scope:                core.JoinScopes(scopes),
		AuthorizationDetails: req.AuthorizationDetails,
	})
}

func (h *TokenEndpointHandler) dispatchAuthorizationCode(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if h.OneAuth == nil || h.OneAuth.AuthorizationCodeGranter == nil {
		h.writeError(w, unsupportedGrantType("authorization_code grant not enabled"))
		return
	}
	audiences := h.acceptedAudiences(r)
	resp, err := h.OneAuth.AuthorizationCodeGranter.AuthorizationCodeGrant(r.Context(), &AuthorizationCodeGrantRequest{
		Code:                req.Code,
		CodeVerifier:        req.CodeVerifier,
		RedirectURI:         req.RedirectURI,
		ClientID:            req.ClientID,
		ClientSecret:        req.ClientSecret,
		ClientAssertionType: req.ClientAssertionType,
		ClientAssertion:     req.ClientAssertion,
		AcceptedAudiences:   audiences,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeTokens(w, resp.Tokens)
}

func (h *TokenEndpointHandler) dispatchDeviceCode(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if h.OneAuth == nil || h.OneAuth.DeviceCodeGranter == nil {
		h.writeError(w, unsupportedGrantType("device authorization grant not enabled"))
		return
	}
	audiences := h.acceptedAudiences(r)
	resp, err := h.OneAuth.DeviceCodeGranter.DeviceCodeGrant(r.Context(), &DeviceCodeGrantRequest{
		DeviceCode:          req.DeviceCode,
		ClientID:            req.ClientID,
		ClientSecret:        req.ClientSecret,
		ClientAssertionType: req.ClientAssertionType,
		ClientAssertion:     req.ClientAssertion,
		AcceptedAudiences:   audiences,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeTokens(w, resp.Tokens)
}

func (h *TokenEndpointHandler) dispatchJwtBearer(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if h.OneAuth == nil || h.OneAuth.JwtBearerGranter == nil {
		h.writeError(w, unsupportedGrantType("jwt-bearer grant not configured"))
		return
	}
	resp, err := h.OneAuth.JwtBearerGranter.JwtBearerGrant(r.Context(), &JwtBearerGrantRequest{
		Assertion:            req.Assertion,
		Scopes:               core.ParseScopes(req.Scope),
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeTokens(w, resp.Tokens)
}

func (h *TokenEndpointHandler) dispatchTokenExchange(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if h.OneAuth == nil || h.OneAuth.TokenExchanger == nil {
		h.writeError(w, unsupportedGrantType("token-exchange grant not configured"))
		return
	}
	resp, err := h.OneAuth.TokenExchanger.TokenExchange(r.Context(), &TokenExchangeRequest{
		SubjectToken:         req.SubjectToken,
		SubjectTokenType:     req.SubjectTokenType,
		RequestedTokenType:   req.RequestedTokenType,
		Resource:             req.Resource,
		Audience:             req.Audience,
		Scopes:               core.ParseScopes(req.Scope),
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeTokens(w, resp.Tokens)
}

// authenticateClient runs whichever auth method the request carries
// through OneAuth.Authenticator. Returns a *GrantError on failure so
// the dispatch sites can surface a consistent invalid_client / 401
// response.
func (h *TokenEndpointHandler) authenticateClient(r *http.Request, req *core.TokenRequest) (string, *GrantError) {
	if h.OneAuth.Authenticator == nil {
		return "", invalidClient("no client authenticator configured")
	}
	creds, ok := extractClientCredentials(r, req)
	if !ok {
		return "", invalidRequest("client credentials required")
	}
	creds.Audiences = h.acceptedAudiences(r)
	resp, err := h.OneAuth.Authenticator.AuthenticateClient(r.Context(), creds)
	if err != nil {
		return "", invalidClient("invalid client credentials")
	}
	if resp == nil || resp.ClientID == "" {
		return "", invalidClient("authenticator returned empty client_id")
	}
	return resp.ClientID, nil
}

// acceptedAudiences returns the configured AcceptedAudiences, falling
// back to the request URL for single-host deployments that don't pin
// the list explicitly.
func (h *TokenEndpointHandler) acceptedAudiences(r *http.Request) []string {
	if h.OneAuth != nil && len(h.OneAuth.AcceptedAudiences) > 0 {
		return h.OneAuth.AcceptedAudiences
	}
	return []string{derivedAudience(r)}
}

// fireOnLoginSuccess invokes Hooks.Auth.OnLoginSuccess when set.
func (h *TokenEndpointHandler) fireOnLoginSuccess(userID string) {
	if h.OneAuth != nil && h.OneAuth.Hooks.Auth.OnLoginSuccess != nil {
		h.OneAuth.Hooks.Auth.OnLoginSuccess(userID)
	}
}

// fireOnLoginFailure invokes Hooks.Auth.OnLoginFailure when set.
func (h *TokenEndpointHandler) fireOnLoginFailure(username string, err error) {
	if h.OneAuth != nil && h.OneAuth.Hooks.Auth.OnLoginFailure != nil {
		h.OneAuth.Hooks.Auth.OnLoginFailure(username, err)
	}
}

// writeTokens emits the RFC 6749 §5.1 success response.
func (h *TokenEndpointHandler) writeTokens(w http.ResponseWriter, tokens *core.TokenPair) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(tokens)
}

// writeError maps a *GrantError (or any error containing one) to the
// RFC 6749 §5.2 error response.
func (h *TokenEndpointHandler) writeError(w http.ResponseWriter, err error) {
	ge, ok := asGrantError(err)
	if !ok {
		ge = serverError(err.Error())
	}
	status := ge.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(core.TokenError{
		Error:            ge.Code,
		ErrorDescription: ge.Description,
	})
}

// HTTPHandler returns an http.Handler bound to OneAuth's TokenEndpointHandler.
// Convenience for callers wiring oa.TokenEndpointHTTPHandler() into a mux.
func (oa *OneAuth) TokenEndpointHTTPHandler() *TokenEndpointHandler {
	return NewTokenEndpointHandler(oa)
}

var _ http.Handler = (*TokenEndpointHandler)(nil)
