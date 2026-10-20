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
// creation delegated to RefreshStore when set; Blacklist revokes the
// access token from a code that is presented twice.
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
	Blacklist     core.TokenBlacklist
}

// NewAuthorizationCodeGranter constructs an AuthorizationCodeGranter
// with the supplied dependencies. Store and Issuer are required;
// AppStore + Authenticator enable confidential-client enforcement;
// RefreshStore enables refresh-token issuance on redemption.
//
// A code presented after it was redeemed is refused, and the tokens the
// first redemption produced are revoked (RFC 6749 §4.1.2): the refresh
// family through RefreshStore and the access token through blacklist.
// With a nil blacklist the access token stays valid until it expires.
func NewAuthorizationCodeGranter(store core.AuthorizationCodeStore, appStore core.AppRegistrationStore, authenticator ClientAuthenticator, issuer TokenIssuer, refreshStore core.RefreshTokenStore, blacklist core.TokenBlacklist) AuthorizationCodeGranter {
	return &authorizationCodeGranter{
		Store:         store,
		AppStore:      appStore,
		Authenticator: authenticator,
		Issuer:        issuer,
		RefreshStore:  refreshStore,
		Blacklist:     blacklist,
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
		// RFC 7636 §4.6 answers a failed PKCE check with invalid_grant,
		// and a missing verifier is one; Keycloak and the OIDF FAPI 2.0
		// plan agree.
		return nil, invalidGrant("code_verifier is required (PKCE)")
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

	// A used code is kept past its own expiry so this check comes first:
	// its record names the tokens to revoke.
	if entry.IsUsed() {
		return nil, r.refuseReuse(ctx, entry.Code)
	}

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
	// RFC 7636 §4.1: 43 to 128 unreserved characters. A shorter one would
	// verify against its own challenge but be guessable.
	if !pkceVerifierShape.MatchString(req.CodeVerifier) {
		return nil, invalidGrant("code_verifier must be 43 to 128 unreserved characters")
	}
	if !core.VerifyPKCE(entry.CodeChallengeMethod, entry.CodeChallenge, req.CodeVerifier) {
		return nil, invalidGrant("PKCE verification failed")
	}

	// RFC 9449 §10: a code issued against a `dpop_jkt` is redeemable
	// only by that key, and the RFC says MUST reject on mismatch. The
	// proven key arrives as req.Confirmation, which the token endpoint
	// fills from the request's DPoP proof, so a request with no proof
	// fails here too. Checked before the code is consumed so a rejected
	// attempt does not burn the legitimate client's code.
	if entry.DPoPJKT != "" && !(&core.Confirmation{JKT: entry.DPoPJKT}).Equal(req.Confirmation) {
		return nil, invalidGrant("authorization code is bound to a different DPoP key")
	}

	// Consume is the single-use gate: of two requests that both read the
	// code, only the first to consume it gets tokens.
	if _, err := r.Store.ConsumeAuthorizationCode(ctx, &core.ConsumeAuthorizationCodeRequest{Code: entry.Code}); err != nil {
		if errors.Is(err, core.ErrAuthorizationCodeUsed) {
			return nil, r.refuseReuse(ctx, entry.Code)
		}
		if errors.Is(err, core.ErrAuthorizationCodeNotFound) {
			return nil, invalidGrant("authorization code not recognized")
		}
		return nil, serverError("consume authorization code: " + err.Error())
	}

	if entry.Subject == "" {
		return nil, invalidGrant("authorization code is missing subject")
	}

	tok, err := r.Issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject:              entry.Subject,
		ClientID:             entry.ClientID,
		Scopes:               entry.Scopes,
		AuthorizationDetails: entry.AuthorizationDetails,
		Confirmation:         req.Confirmation,
	})
	if err != nil {
		return nil, serverError("create access token: " + err.Error())
	}

	issued := core.RecordAuthorizationCodeTokensRequest{
		Code:           entry.Code,
		TokenID:        tok.TokenID,
		TokenExpiresAt: tok.ExpiresAt,
	}
	pair := &core.TokenPair{
		AccessToken:          tok.Token,
		TokenType:            tok.TokenType,
		ExpiresIn:            tok.ExpiresIn,
		Scope:                joinScopes(entry.Scopes),
		AuthorizationDetails: entry.AuthorizationDetails,
	}
	if r.RefreshStore != nil {
		createResp, rtErr := r.RefreshStore.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{
			Subject:      entry.Subject,
			ClientID:     entry.ClientID,
			Scopes:       entry.Scopes,
			Confirmation: refreshConfirmation(authedID, req.Confirmation),
		})
		if rtErr == nil && createResp != nil && createResp.Token != nil {
			pair.RefreshToken = createResp.Token.Token
			issued.RefreshFamily = createResp.Token.Family
			if err := recordAccessToken(ctx, r.RefreshStore, r.Blacklist, pair.RefreshToken, tok.TokenID, tok.ExpiresAt); err != nil {
				r.revoke(ctx, issued.TokenID, issued.TokenExpiresAt, issued.RefreshFamily)
				return nil, serverError("record access token: " + err.Error())
			}
		}
	}

	// The code may have been presented again since it was consumed, before
	// there was anything recorded to revoke. Then these tokens are the
	// ones to revoke, and this redemption is refused too.
	recResp, err := r.Store.RecordAuthorizationCodeTokens(ctx, &issued)
	if err != nil {
		r.revoke(ctx, issued.TokenID, issued.TokenExpiresAt, issued.RefreshFamily)
		return nil, serverError("record authorization code tokens: " + err.Error())
	}
	if recResp.ReuseDetected {
		r.revoke(ctx, issued.TokenID, issued.TokenExpiresAt, issued.RefreshFamily)
		return nil, invalidGrant("authorization code already used")
	}
	return &AuthorizationCodeGrantResponse{Tokens: pair}, nil
}

// refuseReuse handles a code presented after it was redeemed (RFC 6749
// §4.1.2). Consuming it again flags the record, so a redemption still
// in flight refuses its own tokens, and returns the tokens already
// recorded, which are revoked here.
func (r *authorizationCodeGranter) refuseReuse(ctx context.Context, code string) error {
	resp, err := r.Store.ConsumeAuthorizationCode(ctx, &core.ConsumeAuthorizationCodeRequest{Code: code})
	switch {
	case errors.Is(err, core.ErrAuthorizationCodeUsed) && resp != nil && resp.Code != nil:
		c := resp.Code
		r.revoke(ctx, c.IssuedTokenID, c.IssuedTokenExpiresAt, c.IssuedRefreshFamily)
	case errors.Is(err, core.ErrAuthorizationCodeNotFound):
		return invalidGrant("authorization code not recognized")
	case err != nil && !errors.Is(err, core.ErrAuthorizationCodeUsed):
		return serverError("consume authorization code: " + err.Error())
	}
	return invalidGrant("authorization code already used")
}

// revoke blacklists an access token and revokes a refresh family, each
// when there is one to revoke and a store to revoke it in. Access tokens
// minted later by refreshing that family are blacklisted with it.
func (r *authorizationCodeGranter) revoke(ctx context.Context, tokenID string, expiresAt time.Time, family string) {
	if tokenID != "" && r.Blacklist != nil {
		if expiresAt.IsZero() {
			expiresAt = time.Now().Add(core.TokenExpiryAccessToken)
		}
		_ = r.Blacklist.Revoke(tokenID, expiresAt)
	}
	_ = revokeRefreshFamily(ctx, r.RefreshStore, r.Blacklist, family)
}

var _ AuthorizationCodeGranter = (*authorizationCodeGranter)(nil)
