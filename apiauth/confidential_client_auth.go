package apiauth

import (
	"context"
	"errors"
	"log"

	"github.com/panyam/oneauth/core"
)

// clientCredentials carries the raw client-authentication material a grant
// received, decoupled from any one grant's request struct so the shared
// confidential-client gate can consume all grants uniformly.
type clientCredentials struct {
	ClientID            string
	ClientSecret        string
	ClientAssertionType string
	ClientAssertion     string
	Audiences           []string
}

// authenticateConfidentialClient is the shared confidential-client gate for
// the assertion-based grants (jwt-bearer, token-exchange). It enforces client
// authentication when lookupClientID names a registered confidential client,
// mirroring the device_code / authorization_code enforcement (issue 266) but
// keeping the decision in one place so the two new grants — and, later, the
// existing ones — converge on a single implementation.
//
// The decision is a pure function of its inputs (no grant-specific state), so
// the call site can move to a shared dispatch step later without any behavior
// change.
//
// Semantics — deliberately fail-OPEN on an unknown client, UNLIKE device_code:
//
//   - appStore nil, lookupClientID empty, the client is not registered, or its
//     token_endpoint_auth_method is "none" → returns ("", nil), except under
//     FAPI2, where every client authenticates (authenticateFAPIWithoutLookup). The caller
//     keeps the RFC 7523 §3 public / assertion-only path: client auth is
//     OPTIONAL there because the assertion is itself the authorization grant,
//     so an unregistered client_id is a public client, not an error. (device_code
//     fails CLOSED instead because its client_id is bound at authorization time
//     and is therefore known-registered.)
//   - lookupClientID names a registered CONFIDENTIAL client → authenticates the
//     presented creds via the Authenticator. Returns the authenticated
//     client_id, or a *GrantError (invalid_client) when authentication fails or
//     no Authenticator is wired.
//
// lookupClientID (which client's registration decides "confidential?") and
// creds (whose credentials are verified) are separate on purpose: for ID-JAG
// redemption the caller passes the ID-JAG's `client_id` claim as lookupClientID
// — the client the IdP named — while creds carry whatever the presenter sent.
func authenticateConfidentialClient(ctx context.Context, appStore core.AppRegistrationStore, authenticator ClientAuthenticator, lookupClientID string, creds clientCredentials) (string, error) {
	return authenticateClientByRegistration(ctx, appStore, authenticator, lookupClientID, creds, false)
}

// authenticateRegisteredConfidentialClient is the fail-CLOSED sibling of
// authenticateConfidentialClient, for grants whose lookupClientID is already
// known-registered because it was bound at authorization time — device_code
// (RFC 8628) and authorization_code (RFC 6749 §4.1). There, a client_id that
// no longer resolves in the AppStore is anomalous, not a public client, so a
// lookup miss returns invalid_client rather than falling through to the
// assertion-only path.
//
// Everything else matches authenticateConfidentialClient: appStore nil or
// lookupClientID empty → ("", nil) (the caller never wired confidential
// enforcement); method "none" → public; a registered confidential client is
// authenticated and its client_id returned, or invalid_client on failure.
func authenticateRegisteredConfidentialClient(ctx context.Context, appStore core.AppRegistrationStore, authenticator ClientAuthenticator, lookupClientID string, creds clientCredentials) (string, error) {
	return authenticateClientByRegistration(ctx, appStore, authenticator, lookupClientID, creds, true)
}

// authenticateClientByRegistration is the shared implementation behind the
// fail-open and fail-closed gates. failClosedOnMiss selects what an
// unresolvable (registered-but-not-found) client_id means: an error
// (device/authcode) or the public path (jwt-bearer/token-exchange/refresh).
//
// Only core.ErrAppNotFound counts as a miss. Any other store error is a
// server_error in both modes, since reading it as "unregistered" would let
// a confidential client through the fail-open gate unauthenticated.
func authenticateClientByRegistration(ctx context.Context, appStore core.AppRegistrationStore, authenticator ClientAuthenticator, lookupClientID string, creds clientCredentials, failClosedOnMiss bool) (string, error) {
	if isFAPI(authenticator) && (appStore == nil || lookupClientID == "") {
		return authenticateFAPIWithoutLookup(ctx, appStore, authenticator, lookupClientID, creds)
	}
	if appStore == nil || lookupClientID == "" {
		return "", nil
	}
	appResp, err := appStore.GetApp(ctx, &core.GetAppRequest{ClientID: lookupClientID})
	if err != nil && !errors.Is(err, core.ErrAppNotFound) {
		log.Printf("client authentication: look up client %q: %v", lookupClientID, err)
		return "", serverError("could not load the client registration")
	}
	if (err != nil || appResp == nil || appResp.App == nil) && isFAPI(authenticator) {
		// FAPI 2.0 allows confidential clients only, so an unregistered
		// client can't take the public path.
		return "", invalidClient("FAPI 2.0 requires a registered confidential client")
	}
	if err != nil || appResp == nil || appResp.App == nil {
		if failClosedOnMiss {
			return "", invalidClient("unable to resolve client registration")
		}
		// Unregistered client_id → public path (fail-open per RFC 7523 §3).
		return "", nil
	}
	if !isConfidentialAuthMethod(appResp.App.TokenEndpointAuthMethod) {
		if isFAPI(authenticator) {
			return "", invalidClient("FAPI 2.0 allows confidential clients only")
		}
		return "", nil
	}
	if authenticator == nil {
		return "", invalidClient("no client authenticator configured")
	}
	resp, err := authenticator.AuthenticateClient(ctx, &AuthenticateClientRequest{
		ClientID:            creds.ClientID,
		ClientSecret:        creds.ClientSecret,
		ClientAssertionType: creds.ClientAssertionType,
		ClientAssertion:     creds.ClientAssertion,
		Audiences:           creds.Audiences,
	})
	if err != nil || resp == nil || resp.ClientID == "" {
		return "", invalidClient("client authentication required for confidential client")
	}
	return resp.ClientID, nil
}

// authenticateFAPIWithoutLookup covers the requests the registration lookup
// can't: no client_id to look up (jwt-bearer and token-exchange may omit it,
// RFC 7523 §3), or no AppStore. FAPI 2.0 §5.3.2.1 authenticates every client
// regardless, so the credentials name the client (private_key_jwt's `iss`),
// which must then be registered as confidential. Without this a FAPI2 server
// issued tokens to assertion-grant requests that carried no client
// authentication at all (issue 434).
func authenticateFAPIWithoutLookup(ctx context.Context, appStore core.AppRegistrationStore, authenticator ClientAuthenticator, lookupClientID string, creds clientCredentials) (string, error) {
	resp, err := authenticator.AuthenticateClient(ctx, &AuthenticateClientRequest{
		ClientID:            creds.ClientID,
		ClientSecret:        creds.ClientSecret,
		ClientAssertionType: creds.ClientAssertionType,
		ClientAssertion:     creds.ClientAssertion,
		Audiences:           creds.Audiences,
	})
	if err != nil || resp == nil || resp.ClientID == "" {
		return "", invalidClient("FAPI 2.0 requires client authentication")
	}
	if lookupClientID != "" && resp.ClientID != lookupClientID {
		return "", invalidClient("authenticated client does not match client_id")
	}
	if appStore == nil {
		return resp.ClientID, nil
	}
	appResp, err := appStore.GetApp(ctx, &core.GetAppRequest{ClientID: resp.ClientID})
	if err != nil && !errors.Is(err, core.ErrAppNotFound) {
		log.Printf("client authentication: look up client %q: %v", resp.ClientID, err)
		return "", serverError("could not load the client registration")
	}
	if err != nil || appResp == nil || appResp.App == nil || !isConfidentialAuthMethod(appResp.App.TokenEndpointAuthMethod) {
		return "", invalidClient("FAPI 2.0 requires a registered confidential client")
	}
	return resp.ClientID, nil
}

// refreshConfirmation is the DPoP binding a new refresh token carries. RFC
// 9449 §5 binds only a public client's refresh token: a confidential
// client's is already sender-constrained by its client authentication, so it
// stays unbound and each refresh binds its access token to whatever key the
// client proves then. authedID is the client the shared gate authenticated,
// empty when none was.
func refreshConfirmation(authedID string, cnf *core.Confirmation) *core.Confirmation {
	if authedID != "" {
		return nil
	}
	return cnf
}
