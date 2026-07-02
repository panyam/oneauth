package apiauth

import (
	"context"

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
//     token_endpoint_auth_method is "none" → returns ("", nil). The caller
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
// (device/authcode) or the public path (jwt-bearer/token-exchange).
func authenticateClientByRegistration(ctx context.Context, appStore core.AppRegistrationStore, authenticator ClientAuthenticator, lookupClientID string, creds clientCredentials, failClosedOnMiss bool) (string, error) {
	if appStore == nil || lookupClientID == "" {
		return "", nil
	}
	appResp, err := appStore.GetApp(ctx, &core.GetAppRequest{ClientID: lookupClientID})
	if err != nil || appResp == nil || appResp.App == nil {
		if failClosedOnMiss {
			return "", invalidClient("unable to resolve client registration")
		}
		// Unregistered client_id → public path (fail-open per RFC 7523 §3).
		return "", nil
	}
	if !isConfidentialAuthMethod(appResp.App.TokenEndpointAuthMethod) {
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
