package apiauth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/oauth2"
)

// handleAuthorizationCodeGrant is the token endpoint branch for
// grant_type=authorization_code (RFC 6749 §4.1.3). It looks up the
// minted code, re-verifies every binding the AS committed to at
// /authorize time, redeems the code, and issues an access token.
//
// Error taxonomy (RFC 6749 §5.2 + §4.1.3):
//
//	missing AuthorizationCodeStore → 400 unsupported_grant_type
//	missing code / code_verifier / redirect_uri → 400 invalid_request
//	unknown code → 400 invalid_grant
//	expired code → 400 invalid_grant ("authorization code expired")
//	client_id mismatch → 400 invalid_grant
//	redirect_uri mismatch → 400 invalid_grant
//	PKCE verifier mismatch → 400 invalid_grant
//	confidential client without creds → 401 invalid_client
//
// Successful redemption deletes the code so it cannot be replayed for
// a second access token — single-use semantics per RFC 6749 §4.1.2
// ("the authorization code MUST NOT be reused").
//
// Confidential-client enforcement mirrors handleDeviceCodeGrant: when
// AppStore is configured and the registered client's
// `token_endpoint_auth_method` is anything other than `none`, the
// redemption request MUST present credentials that pass the same
// ClientAuthenticator the rest of the token endpoint uses.
func (a *APIAuth) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if a.AuthorizationCodeStore == nil {
		a.errorResponse(w, "unsupported_grant_type", "authorization_code grant not enabled", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		a.errorResponse(w, "invalid_request", "code is required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.CodeVerifier) == "" {
		a.errorResponse(w, "invalid_request", "code_verifier is required (PKCE)", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.RedirectURI) == "" {
		a.errorResponse(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
		return
	}

	getResp, err := a.AuthorizationCodeStore.GetAuthorizationCode(r.Context(), &core.GetAuthorizationCodeRequest{Code: req.Code})
	if err != nil {
		if errors.Is(err, core.ErrAuthorizationCodeNotFound) {
			a.errorResponse(w, "invalid_grant", "authorization code not recognized", http.StatusBadRequest)
			return
		}
		a.errorResponse(w, "server_error", "lookup authorization code: "+err.Error(), http.StatusInternalServerError)
		return
	}
	entry := getResp.Code

	if entry.IsExpired(time.Now()) {
		// Consume the expired record so a leaked-but-stale code cannot
		// be retried indefinitely. Errors here are non-fatal.
		_, _ = a.AuthorizationCodeStore.DeleteAuthorizationCode(r.Context(), &core.DeleteAuthorizationCodeRequest{Code: entry.Code})
		a.errorResponse(w, "invalid_grant", "authorization code expired", http.StatusBadRequest)
		return
	}

	// Confidential-client enforcement: when AppStore is wired and the
	// registered client's auth method is not `none`, require credentials.
	// Mirrors handleDeviceCodeGrant (issue 266).
	effectiveClientID := req.ClientID
	if a.AppStore != nil && entry.ClientID != "" {
		appResp, lookupErr := a.AppStore.GetApp(r.Context(), &core.GetAppRequest{ClientID: entry.ClientID})
		if lookupErr != nil || appResp == nil || appResp.App == nil {
			a.errorResponse(w, "invalid_client", "unable to resolve client registration", http.StatusUnauthorized)
			return
		}
		if isConfidentialAuthMethod(appResp.App.TokenEndpointAuthMethod) {
			authedID, authErr := a.authenticateTokenEndpointClient(r, req)
			if authErr != nil {
				a.errorResponse(w, "invalid_client", "client authentication required for confidential client", http.StatusUnauthorized)
				return
			}
			effectiveClientID = authedID
		}
	}

	// RFC 6749 §4.1.3 binding: the redeemed code MUST be presented by
	// the same client_id that received it. An empty req.ClientID against
	// a bound entry.ClientID is a binding-bypass attempt.
	if entry.ClientID != "" && entry.ClientID != effectiveClientID {
		a.errorResponse(w, "invalid_grant", "authorization code was not issued to this client", http.StatusBadRequest)
		return
	}

	// RFC 6749 §4.1.3: the redirect_uri parameter MUST match the value
	// included in the original /authorize request.
	if entry.RedirectURI != req.RedirectURI {
		a.errorResponse(w, "invalid_grant", "redirect_uri does not match the authorization request", http.StatusBadRequest)
		return
	}

	// RFC 7636 §4.6: verify the PKCE code_verifier against the stored
	// code_challenge using the recorded method. Only S256 is accepted —
	// the /authorize handler rejects everything else.
	if !oauth2.VerifyPKCE(entry.CodeChallengeMethod, entry.CodeChallenge, req.CodeVerifier) {
		a.errorResponse(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		return
	}

	// Consume the code BEFORE issuing the token so a concurrent replay
	// attempt cannot interleave a second redemption. Errors here are
	// fatal — we must not issue if we could not consume.
	if _, err := a.AuthorizationCodeStore.DeleteAuthorizationCode(r.Context(), &core.DeleteAuthorizationCodeRequest{Code: entry.Code}); err != nil {
		a.errorResponse(w, "server_error", "consume authorization code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	subject := entry.Subject
	if subject == "" {
		a.errorResponse(w, "invalid_grant", "authorization code is missing subject", http.StatusBadRequest)
		return
	}

	issuer, err := a.Issuer().CreateAccessToken(r.Context(), &CreateAccessTokenRequest{
		Subject:              subject,
		Scopes:               entry.Scopes,
		AuthorizationDetails: entry.AuthorizationDetails,
	})
	if err != nil {
		a.errorResponse(w, "server_error", "create access token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var refreshToken string
	if a.RefreshTokenStore != nil {
		createResp, rtErr := a.RefreshTokenStore.CreateRefreshToken(r.Context(), &core.CreateRefreshTokenRequest{
			Subject:  subject,
			ClientID: entry.ClientID,
			Scopes:   entry.Scopes,
		})
		if rtErr == nil && createResp != nil && createResp.Token != nil {
			refreshToken = createResp.Token.Token
		}
	}

	a.tokenResponse(w, issuer.Token, issuer.ExpiresIn, refreshToken, entry.Scopes, entry.AuthorizationDetails)
}
