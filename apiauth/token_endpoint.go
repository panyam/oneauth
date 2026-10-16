package apiauth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	// The DPoP proof covers the request, not the grant, so it is checked
	// once here and the resulting key binding is handed to whichever
	// grant runs. A failed proof fails the request before any grant is
	// attempted — a client that meant to get a sender-constrained token
	// must never be handed a bearer token as a consolation prize.
	cnf, gErr := h.dpopConfirmation(w, r)
	if gErr != nil {
		span.SetStatus(codes.Error, gErr.Code)
		h.writeError(w, gErr)
		return
	}
	if cnf != nil {
		span.SetAttributes(attribute.String("oauth.token_type", TokenTypeDPoP))
	} else if gErr := h.requireDPoP(r, req); gErr != nil {
		span.SetStatus(codes.Error, gErr.Code)
		h.writeError(w, gErr)
		return
	}

	switch req.GrantType {
	case "password":
		h.handlePassword(w, r, req, cnf)
	case "refresh_token":
		h.handleRefresh(w, r, req, cnf)
	case "client_credentials":
		h.handleClientCredentials(w, r, req, cnf)
	case AuthorizationCodeGrantType:
		h.dispatchAuthorizationCode(w, r, req, cnf)
	case DeviceCodeGrantType:
		h.dispatchDeviceCode(w, r, req, cnf)
	case JwtBearerGrantType:
		h.dispatchJwtBearer(w, r, req, cnf)
	case TokenExchangeGrantType:
		h.dispatchTokenExchange(w, r, req, cnf)
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
// access-token mint to OneAuth.PasswordGranter. Returns
// unsupported_grant_type when the granter slot is nil (default for
// OAuth 2.1-strict deployments). Per capability-gating umbrella #344.
func (h *TokenEndpointHandler) handlePassword(w http.ResponseWriter, r *http.Request, req *core.TokenRequest, cnf *core.Confirmation) {
	if h.OneAuth == nil {
		h.writeError(w, serverError("token endpoint not configured"))
		return
	}
	if h.OneAuth.PasswordGranter == nil {
		h.writeError(w, unsupportedGrantType("grant_type=password is not enabled (set OneAuthConfig.PasswordGranter to opt in)"))
		return
	}
	if h.RateLimiter != nil {
		key := getClientIP(r) + ":" + req.Username
		if !h.RateLimiter.Allow(key) {
			h.writeError(w, &GrantError{Code: "rate_limit_exceeded", Description: "too many login attempts", Status: http.StatusTooManyRequests})
			return
		}
	}

	resp, err := h.OneAuth.PasswordGranter.PasswordGrant(r.Context(), &PasswordGrantRequest{
		Username:             req.Username,
		Password:             req.Password,
		Scopes:               core.ParseScopes(req.Scope),
		AuthorizationDetails: req.AuthorizationDetails,
		ClientID:             req.ClientID,
		Confirmation:         cnf,
	})
	if err != nil {
		// The granter uses an `invalid_grant: ...` prefix for
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
			Subject:      resp.Subject,
			ClientID:     req.ClientID,
			DeviceInfo:   deviceInfo,
			Scopes:       resp.GrantedScopes,
			Confirmation: cnf,
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
		TokenType:            resp.TokenType,
		ExpiresIn:            resp.ExpiresIn,
		RefreshToken:         refreshTokenStr,
		Scope:                core.JoinScopes(resp.GrantedScopes),
		AuthorizationDetails: resp.AuthorizationDetails,
	})
}

// handleRefresh authenticates the client the refresh token was issued to,
// when that client is registered as confidential, and delegates the rest of
// the grant to TokenIssuer.RefreshGrant, which checks that the token belongs
// to the presenting client (RFC 6749 §6).
func (h *TokenEndpointHandler) handleRefresh(w http.ResponseWriter, r *http.Request, req *core.TokenRequest, cnf *core.Confirmation) {
	if h.OneAuth == nil || h.OneAuth.Issuer == nil {
		h.writeError(w, serverError("token endpoint not configured"))
		return
	}
	if req.RefreshToken == "" {
		h.writeError(w, invalidRequest("refresh_token is required"))
		return
	}
	clientID, gErr := h.refreshingClient(r, req)
	if gErr != nil {
		h.writeError(w, gErr)
		return
	}
	resp, err := h.OneAuth.Issuer.RefreshGrant(r.Context(), &RefreshGrantRequest{
		RefreshToken: req.RefreshToken,
		ClientID:     clientID,
		Confirmation: cnf,
	})
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "invalid_grant"), strings.Contains(msg, "expired"), strings.Contains(msg, "revoked"), strings.Contains(msg, "reuse"):
			h.writeError(w, &GrantError{Code: "invalid_grant", Description: msg, Status: http.StatusBadRequest})
		default:
			log.Printf("refresh grant: %v", err)
			h.writeError(w, serverError("refresh grant failed"))
		}
		return
	}
	h.writeTokens(w, resp.Tokens)
}

// refreshingClient returns the client a refresh request comes from. A
// request naming a client other than the token's owner is returned as is,
// for RefreshGrant to refuse as invalid_grant. Otherwise the registration
// consulted is the owner's, so if the owner is confidential the presented
// credentials must authenticate, and the authenticated client_id is
// returned. Otherwise (a public or unregistered
// owner, an unknown token, no AppStore) the request's own client_id is
// returned unverified, and RefreshGrant's match against the owner is the
// check. A request naming no client for a token that has one is
// invalid_client. The owner lookup is fail-open on an unregistered client because
// the SDK's Login issues tokens to "cli", which nothing registers.
func (h *TokenEndpointHandler) refreshingClient(r *http.Request, req *core.TokenRequest) (string, *GrantError) {
	clientID, clientSecret, assertionType, assertion := dispatchClientCredentials(r, req)
	owner := refreshTokenOwner(r, h.OneAuth, req)
	if owner != "" && clientID != "" && clientID != owner {
		// Naming another client can't succeed, so RefreshGrant's match
		// refuses it as invalid_grant without asking for credentials.
		return clientID, nil
	}
	authedID, err := authenticateConfidentialClient(r.Context(), h.OneAuth.AppStore, h.OneAuth.Authenticator, owner, clientCredentials{
		ClientID:            clientID,
		ClientSecret:        clientSecret,
		ClientAssertionType: assertionType,
		ClientAssertion:     assertion,
		Audiences:           h.acceptedAudiences(r),
	})
	if err != nil {
		if ge, ok := asGrantError(err); ok {
			return "", ge
		}
		return "", invalidClient("client authentication failed")
	}
	if authedID != "" {
		return authedID, nil
	}
	// A request that names no client for a token that has one included no
	// client authentication at all, which RFC 6749 §5.2 calls
	// invalid_client. Keycloak answers the same way.
	if clientID == "" && owner != "" {
		return "", invalidClient("client_id is required to refresh this token")
	}
	return clientID, nil
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
func (h *TokenEndpointHandler) handleClientCredentials(w http.ResponseWriter, r *http.Request, req *core.TokenRequest, cnf *core.Confirmation) {
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
		Confirmation:         cnf,
	})
	if err != nil {
		log.Printf("client_credentials mint: %v", err)
		h.writeError(w, serverError("failed to create token"))
		return
	}

	h.writeTokens(w, &core.TokenPair{
		AccessToken:          tok.Token,
		TokenType:            tok.TokenType,
		ExpiresIn:            tok.ExpiresIn,
		Scope:                core.JoinScopes(scopes),
		AuthorizationDetails: req.AuthorizationDetails,
	})
}

// dispatchClientCredentials resolves the client credentials for the grants
// whose dispatch forwards them to a confidential-client gate
// (authorization_code, device_code, jwt-bearer, token-exchange). It runs the
// shared extractClientCredentials, which resolves all three OAuth channels —
// Authorization: Basic (RFC 6749 §2.3.1), client_secret_post form params, and
// client_assertion (RFC 7521 §4.2) — so a client_secret_basic credential in
// the Authorization header is honored, not just what parseTokenRequest read
// from the form body.
//
// Unlike client_credentials, these grants permit a public client that sends no
// credentials (the assertion / PKCE / device binding is the proof), so a
// no-match is not an error: it falls back to the form-derived client_id/secret
// so the downstream confidential-client lookup — which keys off client_id — is
// preserved for the public / assertion-only path.
func dispatchClientCredentials(r *http.Request, req *core.TokenRequest) (clientID, clientSecret, assertionType, assertion string) {
	if creds, ok := extractClientCredentials(r, req); ok {
		return creds.ClientID, creds.ClientSecret, creds.ClientAssertionType, creds.ClientAssertion
	}
	return req.ClientID, req.ClientSecret, req.ClientAssertionType, req.ClientAssertion
}

func (h *TokenEndpointHandler) dispatchAuthorizationCode(w http.ResponseWriter, r *http.Request, req *core.TokenRequest, cnf *core.Confirmation) {
	if h.OneAuth == nil || h.OneAuth.AuthorizationCodeGranter == nil {
		h.writeError(w, unsupportedGrantType("authorization_code grant not enabled"))
		return
	}
	audiences := h.acceptedAudiences(r)
	clientID, clientSecret, assertionType, assertion := dispatchClientCredentials(r, req)
	resp, err := h.OneAuth.AuthorizationCodeGranter.AuthorizationCodeGrant(r.Context(), &AuthorizationCodeGrantRequest{
		Code:                req.Code,
		CodeVerifier:        req.CodeVerifier,
		RedirectURI:         req.RedirectURI,
		ClientID:            clientID,
		ClientSecret:        clientSecret,
		ClientAssertionType: assertionType,
		ClientAssertion:     assertion,
		AcceptedAudiences:   audiences,
		Confirmation:        cnf,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeTokens(w, resp.Tokens)
}

func (h *TokenEndpointHandler) dispatchDeviceCode(w http.ResponseWriter, r *http.Request, req *core.TokenRequest, cnf *core.Confirmation) {
	if h.OneAuth == nil || h.OneAuth.DeviceCodeGranter == nil {
		h.writeError(w, unsupportedGrantType("device authorization grant not enabled"))
		return
	}
	audiences := h.acceptedAudiences(r)
	clientID, clientSecret, assertionType, assertion := dispatchClientCredentials(r, req)
	resp, err := h.OneAuth.DeviceCodeGranter.DeviceCodeGrant(r.Context(), &DeviceCodeGrantRequest{
		DeviceCode:          req.DeviceCode,
		ClientID:            clientID,
		ClientSecret:        clientSecret,
		ClientAssertionType: assertionType,
		ClientAssertion:     assertion,
		AcceptedAudiences:   audiences,
		Confirmation:        cnf,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeTokens(w, resp.Tokens)
}

func (h *TokenEndpointHandler) dispatchJwtBearer(w http.ResponseWriter, r *http.Request, req *core.TokenRequest, cnf *core.Confirmation) {
	if h.OneAuth == nil || h.OneAuth.JwtBearerGranter == nil {
		h.writeError(w, unsupportedGrantType("jwt-bearer grant not configured"))
		return
	}
	clientID, clientSecret, assertionType, assertion := dispatchClientCredentials(r, req)
	resp, err := h.OneAuth.JwtBearerGranter.JwtBearerGrant(r.Context(), &JwtBearerGrantRequest{
		Assertion:            req.Assertion,
		Scopes:               core.ParseScopes(req.Scope),
		AuthorizationDetails: req.AuthorizationDetails,
		ClientID:             clientID,
		ClientSecret:         clientSecret,
		ClientAssertionType:  assertionType,
		ClientAssertion:      assertion,
		AcceptedAudiences:    h.acceptedAudiences(r),
		Confirmation:         cnf,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeTokens(w, resp.Tokens)
}

func (h *TokenEndpointHandler) dispatchTokenExchange(w http.ResponseWriter, r *http.Request, req *core.TokenRequest, cnf *core.Confirmation) {
	if h.OneAuth == nil || h.OneAuth.TokenExchanger == nil {
		h.writeError(w, unsupportedGrantType("token-exchange grant not configured"))
		return
	}
	clientID, clientSecret, assertionType, assertion := dispatchClientCredentials(r, req)
	resp, err := h.OneAuth.TokenExchanger.TokenExchange(r.Context(), &TokenExchangeRequest{
		SubjectToken:         req.SubjectToken,
		SubjectTokenType:     req.SubjectTokenType,
		RequestedTokenType:   req.RequestedTokenType,
		Resource:             req.Resource,
		Audience:             req.Audience,
		Scopes:               core.ParseScopes(req.Scope),
		AuthorizationDetails: req.AuthorizationDetails,
		ClientID:             clientID,
		ClientSecret:         clientSecret,
		ClientAssertionType:  assertionType,
		ClientAssertion:      assertion,
		AcceptedAudiences:    h.acceptedAudiences(r),
		Confirmation:         cnf,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeTokens(w, resp.Tokens)
}

// dpopConfirmation validates the request's DPoP proof, if any, and
// returns the key binding to apply to the issued tokens.
//
// Three outcomes: no validator wired returns (nil, nil) and the AS stays
// bearer-only, so a client that sends a proof to a non-DPoP deployment
// still gets a working bearer token (RFC 9449 §5); a validator wired but
// no proof sent returns (nil, nil) because DPoP is per-request opt-in; a
// proof that fails any check returns an invalid_dpop_proof GrantError.
func (h *TokenEndpointHandler) dpopConfirmation(w http.ResponseWriter, r *http.Request) (*core.Confirmation, *GrantError) {
	if h.OneAuth == nil || h.OneAuth.DPoP == nil {
		return nil, nil
	}
	cnf, err := h.OneAuth.DPoP.Confirm(r.Context(), r)
	if err != nil {
		// RFC 9449 §8: a missing or stale nonce is answered with
		// use_dpop_nonce plus the value to retry with, not with a
		// proof rejection. The client is expected to try again
		// immediately, so this is part of the handshake.
		var nonceErr *NonceRequiredError
		if errors.As(err, &nonceErr) {
			writeNonceHeader(w, nonceErr)
			return nil, &GrantError{Code: ErrorUseDPoPNonce, Description: nonceErr.Error(), Status: http.StatusBadRequest}
		}
		if ge, ok := asGrantError(err); ok {
			return nil, ge
		}
		return nil, invalidDPoPProof(err.Error())
	}
	return cnf, nil
}

// requireDPoP refuses a request that carries no DPoP proof when the AS
// (OneAuth.RequireDPoP) or the requesting client (RFC 9449 §5.2
// dpop_bound_access_tokens) demands one. It runs before any grant, so no
// grant can hand out a bearer token in place of a bound one.
//
// The client is identified the way client authentication will identify it:
// Basic auth, client_id, or a client assertion's sub. The refresh grant is
// the exception: it uses the refresh token's own owner, so the policy is
// settled by the token before the grant gets to check the client. The registration lookup happens before
// authentication, which means an unauthenticated caller can learn that a
// client_id requires DPoP. It learns nothing else, and the alternative is a
// check in every grant.
//
// A store error other than not-found fails closed with server_error, since
// treating it as "not bound" would issue a bearer token to a bound client.
func (h *TokenEndpointHandler) requireDPoP(r *http.Request, req *core.TokenRequest) *GrantError {
	oa := h.OneAuth
	if oa == nil {
		return nil
	}
	if !oa.RequireDPoP {
		if oa.AppStore == nil {
			return nil
		}
		clientID := refreshTokenOwner(r, oa, req)
		if clientID == "" {
			clientID = requestingClientID(r, req)
		}
		if clientID == "" {
			return nil
		}
		resp, err := oa.AppStore.GetApp(r.Context(), &core.GetAppRequest{ClientID: clientID})
		if err != nil && !errors.Is(err, core.ErrAppNotFound) {
			log.Printf("token endpoint: look up client %q for dpop_bound_access_tokens: %v", clientID, err)
			return serverError("could not load the client registration")
		}
		if err != nil || resp == nil || resp.App == nil || !resp.App.DPoPBoundAccessTokens {
			return nil
		}
	}
	if oa.DPoP == nil {
		return serverError("DPoP is required but no DPoP validator is configured")
	}
	return invalidDPoPProof("a DPoP proof is required")
}

// refreshTokenOwner returns the client a refresh_token request's token was
// issued to, or "" for any other grant, an unknown token, or no store.
func refreshTokenOwner(r *http.Request, oa *OneAuth, req *core.TokenRequest) string {
	if req == nil || req.GrantType != "refresh_token" || req.RefreshToken == "" || oa.RefreshStore == nil {
		return ""
	}
	resp, err := oa.RefreshStore.GetRefreshToken(r.Context(), &core.GetRefreshTokenRequest{Token: req.RefreshToken})
	if err != nil || resp == nil || resp.Token == nil {
		return ""
	}
	return resp.Token.ClientID
}

// requestingClientID names the client a token request comes from, without
// authenticating it.
func requestingClientID(r *http.Request, req *core.TokenRequest) string {
	if creds, ok := extractClientCredentials(r, req); ok {
		if creds.ClientID != "" {
			return creds.ClientID
		}
		if creds.ClientAssertion != "" {
			claims := jwt.MapClaims{}
			if _, _, err := jwt.NewParser().ParseUnverified(creds.ClientAssertion, claims); err == nil {
				if sub, _ := claims["sub"].(string); sub != "" {
					return sub
				}
			}
		}
	}
	if req != nil && req.ClientID != "" {
		return req.ClientID
	}
	return r.FormValue("client_id")
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
