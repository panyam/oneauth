package apiauth

import (
	"context"
	"errors"
	"time"

	"github.com/panyam/oneauth/core"
)

// authorizationCodeGranter implements AuthorizationCodeGranter
// (RFC 6749 §4.1.3 redemption). Each field is exactly what the
// operation requires: lookups via Store; confidential-client
// enforcement via AppStore + Authenticator (issue 266); PKCE verify
// via core.VerifyPKCE; token mint delegated to Issuer; refresh-token
// creation delegated to RefreshStore when set.
//
// The legacy APIAuth.handleAuthorizationCodeGrant (in authorize_grant.go)
// is preserved for the transition window so existing consumers keep
// working until they migrate to TokenEndpointHandler.
type authorizationCodeGranter struct {
	Store         core.AuthorizationCodeStore
	AppStore      core.AppRegistrationStore
	Authenticator ClientAuthenticator
	Issuer        TokenIssuer
	RefreshStore  core.RefreshTokenStore
}

// NewAuthorizationCodeGranter constructs an AuthorizationCodeGranter
// with the supplied dependencies. Store and Issuer are required;
// AppStore + Authenticator enable confidential-client enforcement;
// RefreshStore enables refresh-token issuance on redemption.
func NewAuthorizationCodeGranter(store core.AuthorizationCodeStore, appStore core.AppRegistrationStore, authenticator ClientAuthenticator, issuer TokenIssuer, refreshStore core.RefreshTokenStore) AuthorizationCodeGranter {
	return &authorizationCodeGranter{
		Store:         store,
		AppStore:      appStore,
		Authenticator: authenticator,
		Issuer:        issuer,
		RefreshStore:  refreshStore,
	}
}

// AuthorizationCodeGrant redeems a code per RFC 6749 §4.1.3. See
// the AuthorizationCodeGranter interface comment for the error
// taxonomy. Behavior matches the legacy
// APIAuth.handleAuthorizationCodeGrant; only the transport shape
// differs (typed *GrantError vs inline HTTP writes).
func (r *authorizationCodeGranter) AuthorizationCodeGrant(ctx context.Context, req *AuthorizationCodeGrantRequest) (*AuthorizationCodeGrantResponse, error) {
	if r.Store == nil {
		return nil, unsupportedGrantType("authorization_code grant not enabled")
	}
	if req == nil {
		return nil, invalidRequest("request is required")
	}
	if req.Code == "" {
		return nil, invalidRequest("code is required")
	}
	if req.CodeVerifier == "" {
		return nil, invalidRequest("code_verifier is required (PKCE)")
	}
	if req.RedirectURI == "" {
		return nil, invalidRequest("redirect_uri is required")
	}

	getResp, err := r.Store.GetAuthorizationCode(ctx, &core.GetAuthorizationCodeRequest{Code: req.Code})
	if err != nil {
		if errors.Is(err, core.ErrAuthorizationCodeNotFound) {
			return nil, invalidGrant("authorization code not recognized")
		}
		return nil, serverError("lookup authorization code: " + err.Error())
	}
	entry := getResp.Code

	if entry.IsExpired(time.Now()) {
		_, _ = r.Store.DeleteAuthorizationCode(ctx, &core.DeleteAuthorizationCodeRequest{Code: entry.Code})
		return nil, invalidGrant("authorization code expired")
	}

	// Confidential-client authentication (issue 266), fail-CLOSED: the code
	// was bound to entry.ClientID at authorization time, so an unresolvable
	// registration is anomalous. Shared gate — issue 358.
	authedID, authErr := authenticateRegisteredConfidentialClient(ctx, r.AppStore, r.Authenticator, entry.ClientID, clientCredentials{
		ClientID:            req.ClientID,
		ClientSecret:        req.ClientSecret,
		ClientAssertionType: req.ClientAssertionType,
		ClientAssertion:     req.ClientAssertion,
		Audiences:           req.AcceptedAudiences,
	})
	if authErr != nil {
		return nil, authErr
	}
	effectiveClientID := req.ClientID
	if authedID != "" {
		effectiveClientID = authedID
	}

	if entry.ClientID != "" && entry.ClientID != effectiveClientID {
		return nil, invalidGrant("authorization code was not issued to this client")
	}
	if entry.RedirectURI != req.RedirectURI {
		return nil, invalidGrant("redirect_uri does not match the authorization request")
	}
	if !core.VerifyPKCE(entry.CodeChallengeMethod, entry.CodeChallenge, req.CodeVerifier) {
		return nil, invalidGrant("PKCE verification failed")
	}

	if _, err := r.Store.DeleteAuthorizationCode(ctx, &core.DeleteAuthorizationCodeRequest{Code: entry.Code}); err != nil {
		return nil, serverError("consume authorization code: " + err.Error())
	}

	if entry.Subject == "" {
		return nil, invalidGrant("authorization code is missing subject")
	}

	tok, err := r.Issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject:              entry.Subject,
		Scopes:               entry.Scopes,
		AuthorizationDetails: entry.AuthorizationDetails,
	})
	if err != nil {
		return nil, serverError("create access token: " + err.Error())
	}

	pair := &core.TokenPair{
		AccessToken:          tok.Token,
		TokenType:            "Bearer",
		ExpiresIn:            tok.ExpiresIn,
		Scope:                joinScopes(entry.Scopes),
		AuthorizationDetails: entry.AuthorizationDetails,
	}
	if r.RefreshStore != nil {
		createResp, rtErr := r.RefreshStore.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{
			Subject:  entry.Subject,
			ClientID: entry.ClientID,
			Scopes:   entry.Scopes,
		})
		if rtErr == nil && createResp != nil && createResp.Token != nil {
			pair.RefreshToken = createResp.Token.Token
		}
	}
	return &AuthorizationCodeGrantResponse{Tokens: pair}, nil
}

var _ AuthorizationCodeGranter = (*authorizationCodeGranter)(nil)
