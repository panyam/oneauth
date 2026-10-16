package apiauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/panyam/oneauth/core"
)

// clientRegistration returns clientID's registration, or nil when there is
// no AppStore, no client, or no registration. A nil registration places no
// limits: KeyStore-only clients keep working as before. A store failure is
// server_error rather than "no registration", or an outage would lift
// every client's limits.
func clientRegistration(ctx context.Context, store core.AppRegistrationStore, clientID string) (*core.AppRegistration, *GrantError) {
	if store == nil || clientID == "" {
		return nil, nil
	}
	resp, err := store.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	if errors.Is(err, core.ErrAppNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, serverError(fmt.Sprintf("look up client %q: %v", clientID, err))
	}
	if resp == nil {
		return nil, nil
	}
	return resp.App, nil
}

// grantScopes applies a client's registered scope (RFC 7591 §2 "scope") to
// the scopes it asked for. A scope outside the registration is
// invalid_scope (RFC 6749 §5.2) rather than silently dropped, so a
// misconfigured client finds out. Asking for nothing gets the registered
// scope, as RFC 6749 §3.3 allows. A registration with no scope, or no
// registration, passes the request through.
func grantScopes(reg *core.AppRegistration, requested []string) ([]string, *GrantError) {
	if reg == nil || reg.Scope == "" {
		return requested, nil
	}
	allowed := core.ParseScopes(reg.Scope)
	if len(requested) == 0 {
		return allowed, nil
	}
	for _, s := range requested {
		if !slices.Contains(allowed, s) {
			return nil, invalidScope(fmt.Sprintf("scope %q is not registered for this client", s))
		}
	}
	return requested, nil
}

// checkRARTypes refuses authorization_details whose type the client didn't
// register (RFC 9396 §5, authorization_details_types in RFC 7591 metadata).
// A registration listing no types, or no registration, allows any type.
func checkRARTypes(reg *core.AppRegistration, details []core.AuthorizationDetail) *GrantError {
	if reg == nil || len(reg.AuthorizationDetailsTypes) == 0 {
		return nil
	}
	for _, d := range details {
		if !slices.Contains(reg.AuthorizationDetailsTypes, d.Type) {
			return &GrantError{Code: "invalid_authorization_details", Description: fmt.Sprintf("authorization_details type %q is not registered for this client", d.Type), Status: http.StatusBadRequest}
		}
	}
	return nil
}

// invalidScope is RFC 6749 §5.2's invalid_scope.
func invalidScope(description string) *GrantError {
	return &GrantError{Code: "invalid_scope", Description: description, Status: http.StatusBadRequest}
}
