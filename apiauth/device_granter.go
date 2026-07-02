package apiauth

import (
	"context"
	"time"

	"github.com/panyam/oneauth/core"
)

// deviceCodeGranter implements DeviceCodeGranter (RFC 8628 §3.4
// device-code redemption). Maps the stored DeviceAuthorization status
// + polling clock to the §3.5 error taxonomy, enforces confidential-
// client authentication via AppStore + Authenticator (issue 266) and
// delegates the token mint to Issuer on Approved status.
//
// The legacy APIAuth.handleDeviceCodeGrant (in device_auth_grant.go)
// is preserved for the transition window so existing consumers keep
// working until they migrate to TokenEndpointHandler.
type deviceCodeGranter struct {
	Store         core.DeviceAuthorizationStore
	AppStore      core.AppRegistrationStore
	Authenticator ClientAuthenticator
	Issuer        TokenIssuer
	RefreshStore  core.RefreshTokenStore
}

// NewDeviceCodeGranter constructs a DeviceCodeGranter. Store and
// Issuer are required; AppStore + Authenticator enable confidential-
// client enforcement; RefreshStore enables refresh-token issuance on
// redemption.
func NewDeviceCodeGranter(store core.DeviceAuthorizationStore, appStore core.AppRegistrationStore, authenticator ClientAuthenticator, issuer TokenIssuer, refreshStore core.RefreshTokenStore) DeviceCodeGranter {
	return &deviceCodeGranter{
		Store:         store,
		AppStore:      appStore,
		Authenticator: authenticator,
		Issuer:        issuer,
		RefreshStore:  refreshStore,
	}
}

// DeviceCodeGrant polls / redeems a device_code per RFC 8628 §3.4 +
// §3.5. Behavior matches the legacy APIAuth.handleDeviceCodeGrant;
// only the transport shape differs (typed *GrantError vs inline HTTP
// writes).
func (r *deviceCodeGranter) DeviceCodeGrant(ctx context.Context, req *DeviceCodeGrantRequest) (*DeviceCodeGrantResponse, error) {
	if r.Store == nil {
		return nil, unsupportedGrantType("device authorization grant not enabled")
	}
	if req == nil {
		return nil, invalidRequest("request is required")
	}
	if req.DeviceCode == "" {
		return nil, invalidRequest("device_code is required")
	}

	getResp, err := r.Store.GetByDeviceCode(ctx, &core.GetByDeviceCodeRequest{DeviceCode: req.DeviceCode})
	if err != nil {
		return nil, invalidGrant("device_code not recognized")
	}
	auth := getResp.Authorization

	// Confidential-client authentication (issue 266), fail-CLOSED: the
	// device_code was bound to auth.ClientID at authorization time, so an
	// unresolvable registration is anomalous. Shared gate — issue 358.
	authedID, authErr := authenticateRegisteredConfidentialClient(ctx, r.AppStore, r.Authenticator, auth.ClientID, clientCredentials{
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

	if auth.ClientID != "" && auth.ClientID != effectiveClientID {
		return nil, invalidGrant("device_code was not issued to this client")
	}

	now := time.Now()
	if auth.IsExpired(now) {
		return nil, &GrantError{Code: "expired_token", Description: "device_code expired", Status: 400}
	}

	switch auth.Status {
	case core.DeviceAuthorizationStatusDenied:
		return nil, &GrantError{Code: "access_denied", Description: "user denied the authorization", Status: 400}
	case core.DeviceAuthorizationStatusPending:
		slow := !auth.LastPolledAt.IsZero() && now.Sub(auth.LastPolledAt) < time.Duration(auth.IntervalSeconds)*time.Second
		_, _ = r.Store.UpdatePollingState(ctx, &core.UpdatePollingStateRequest{
			DeviceCode: auth.DeviceCode,
			PolledAt:   now,
			SlowDown:   slow,
		})
		if slow {
			return nil, &GrantError{Code: "slow_down", Description: "polling too quickly", Status: 400}
		}
		return nil, &GrantError{Code: "authorization_pending", Description: "user has not yet completed the authorization", Status: 400}
	case core.DeviceAuthorizationStatusApproved:
		// fall through to issuance
	default:
		return nil, invalidGrant("device authorization in unknown state")
	}

	subject := auth.ApprovedSubject
	if subject == "" {
		return nil, invalidGrant("approved authorization is missing subject")
	}

	tok, err := r.Issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject: subject,
		Scopes:  auth.Scopes,
	})
	if err != nil {
		return nil, serverError("create access token: " + err.Error())
	}

	pair := &core.TokenPair{
		AccessToken: tok.Token,
		TokenType:   "Bearer",
		ExpiresIn:   tok.ExpiresIn,
		Scope:       joinScopes(auth.Scopes),
	}
	if r.RefreshStore != nil {
		createResp, rtErr := r.RefreshStore.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{
			Subject:  subject,
			ClientID: auth.ClientID,
			Scopes:   auth.Scopes,
		})
		if rtErr == nil && createResp != nil && createResp.Token != nil {
			pair.RefreshToken = createResp.Token.Token
		}
	}

	// Consume after issuance (matches legacy behavior — non-fatal).
	_, _ = r.Store.DeleteDeviceAuthorization(ctx, &core.DeleteDeviceAuthorizationRequest{DeviceCode: auth.DeviceCode})

	return &DeviceCodeGrantResponse{Tokens: pair}, nil
}

var _ DeviceCodeGranter = (*deviceCodeGranter)(nil)
