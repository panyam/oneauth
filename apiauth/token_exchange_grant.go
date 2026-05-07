package apiauth

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/panyam/oneauth/core"
)

// TokenExchangeGrantType is the OAuth grant type URI for OAuth 2.0
// Token Exchange (RFC 8693 §2.1). A client presents a `subject_token`
// representing the party on whose behalf the request is made and the
// AS issues a new token (typically narrower in scope or audience).
//
// Common use case: enterprise-managed identity chains. A federated IdP
// issues a JWT about an employee; the employee's MCP client trades that
// JWT for an MCP-scoped access token via this grant.
//
// See: https://www.rfc-editor.org/rfc/rfc8693
const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// RFC 8693 §3 token type URIs.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
)

// handleTokenExchangeGrant handles RFC 8693 token exchange.
//
// Phase 1 implementation supports:
//
//   - subject_token_type = urn:ietf:params:oauth:token-type:jwt — the
//     subject_token is parsed + validated as a JWT against the configured
//     TrustedAssertionIssuers (reusing validateAssertion shared with the
//     jwt-bearer grant from RFC 7523 §2.1).
//   - requested_token_type = urn:ietf:params:oauth:token-type:access_token
//     (default; if omitted) or unspecified. Other requested_token_type
//     values return invalid_request — non-access-token issuance lands in
//     a future commit.
//
// audience / resource params are accepted but currently advisory — the
// issued access token still carries the AS's default JWTAudience claim.
// Active audience binding (CreateAccessToken-with-target-audience) is
// future work; the spec gap is logged so it surfaces in production.
//
// Response shape per RFC 8693 §2.2:
//
//	{
//	  "access_token":       "...",
//	  "issued_token_type":  "urn:ietf:params:oauth:token-type:access_token",
//	  "token_type":         "Bearer",
//	  "expires_in":         900,
//	  "scope":              "read write"
//	}
//
// `issued_token_type` is REQUIRED in token-exchange responses (distinct
// from the standard token-endpoint response shape used by other grants).
func (a *APIAuth) handleTokenExchangeGrant(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if len(a.TrustedAssertionIssuers) == 0 {
		a.errorResponse(w, "unsupported_grant_type", "token-exchange grant not configured", http.StatusBadRequest)
		return
	}
	if req.SubjectToken == "" {
		a.errorResponse(w, "invalid_request", "subject_token parameter required", http.StatusBadRequest)
		return
	}
	if req.SubjectTokenType == "" {
		a.errorResponse(w, "invalid_request", "subject_token_type parameter required", http.StatusBadRequest)
		return
	}

	// Phase 1: only JWT subject tokens are validated. Other types return
	// invalid_request — extending to id_token / refresh_token / SAML
	// requires per-type validators.
	if req.SubjectTokenType != TokenTypeJWT {
		a.errorResponse(w, "invalid_request",
			"only subject_token_type="+TokenTypeJWT+" is supported",
			http.StatusBadRequest)
		return
	}

	// Phase 1: only access_token output. Default when omitted.
	requestedType := req.RequestedTokenType
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}
	if requestedType != TokenTypeAccessToken {
		a.errorResponse(w, "invalid_request",
			"only requested_token_type="+TokenTypeAccessToken+" is supported",
			http.StatusBadRequest)
		return
	}

	// Reuse the assertion validator from RFC 7523 — same iss/sig/aud/exp/sub
	// validation rules apply to the token-exchange subject_token when it's
	// a JWT (RFC 8693 §2.1.1 + RFC 7523 §3).
	claims, _, err := validateAssertion(a, req.SubjectToken)
	if err != nil {
		a.errorResponse(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}

	subject, _ := claims["sub"].(string)
	scopes := core.ParseScopes(req.Scope)

	// audience / resource are advisory in this implementation. Log when
	// they're set so production deployments notice the gap.
	if req.Audience != "" || req.Resource != "" {
		log.Printf("apiauth: token-exchange — audience=%q resource=%q params accepted but advisory; issued token uses default JWTAudience. Bind these into CreateAccessToken when audience-targeting lands.", req.Audience, req.Resource)
	}

	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		a.errorResponse(w, "invalid_authorization_details", err.Error(), http.StatusBadRequest)
		return
	}

	accessToken, expiresIn, err := a.CreateAccessToken(subject, scopes, req.AuthorizationDetails)
	if err != nil {
		log.Printf("Error creating access token (token-exchange grant): %v", err)
		a.errorResponse(w, "server_error", "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Token-exchange has its own response shape — the standard
	// tokenResponse helper omits issued_token_type, which RFC 8693 §2.2
	// REQUIRES. Encode the response inline.
	resp := core.TokenPair{
		AccessToken:          accessToken,
		TokenType:            "Bearer",
		ExpiresIn:            expiresIn,
		Scope:                core.JoinScopes(scopes),
		AuthorizationDetails: req.AuthorizationDetails,
		IssuedTokenType:      requestedType,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}
