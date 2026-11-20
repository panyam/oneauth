package apiauth

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"

	"github.com/panyam/oneauth/core"
)

// Implicit response types (OIDC Core §3.2). Hybrid types such as
// "code id_token" are not supported.
const (
	ResponseTypeIDToken      = "id_token"
	ResponseTypeIDTokenToken = "id_token token"
)

// ImplicitTokens mints what the implicit flow returns from /authorize:
// the access token for "id_token token", and the ID token. MountAuthorize
// fills it from OneAuth when OneAuthConfig.AllowImplicit is set.
type ImplicitTokens struct {
	Issuer   TokenIssuer
	IDTokens IDTokenIssuer
}

// isImplicit reports whether req asks for an implicit response type on a
// handler that serves them. On one that doesn't, the type is just
// unsupported, and its error goes in the query as before.
func (h *AuthorizationHandler) isImplicit(req *AuthorizationRequest) bool {
	return h.Implicit != nil && req != nil && (req.ResponseType == ResponseTypeIDToken || req.ResponseType == ResponseTypeIDTokenToken)
}

// validateImplicit checks an implicit request against the client's
// registration (reg, nil when there is no AppStore): the client must have
// registered this response type, the scope must include openid, and a
// nonce is required (OIDC Core §3.2.2.1). It returns an OAuth error code
// and description, or "" when the request is fine.
func validateImplicit(req *AuthorizationRequest, reg *core.AppRegistration) (string, string) {
	if reg == nil || !slices.Contains(reg.ResponseTypes, req.ResponseType) {
		return "unauthorized_client", fmt.Sprintf("the client is not registered for response_type %q", req.ResponseType)
	}
	if !slices.Contains(req.Scopes(), core.ScopeOpenID) {
		return "invalid_scope", "the implicit flow needs the openid scope"
	}
	if req.Nonce == "" {
		return "invalid_request", "nonce is required for the implicit flow (OIDC Core §3.2.2.1)"
	}
	return "", ""
}

// ImplicitRedirect mints the implicit flow's tokens for subject and
// composes the success redirect, with every parameter in the fragment
// (OIDC Core §3.2.2.5):
//
//	<redirect_uri>#[access_token=…&token_type=Bearer&expires_in=…&scope=…&]id_token=…[&state=…][&iss=…]
//
// The ID token carries the nonce, and at_hash when an access token is
// issued. For "id_token" alone the scope's claims go in the ID token,
// since no access token reaches userinfo (OIDC Core §5.4). No refresh
// token is issued.
func (h *AuthorizationHandler) ImplicitRedirect(ctx context.Context, req *AuthorizationRequest, subject string) (string, error) {
	if !h.isImplicit(req) {
		return "", fmt.Errorf("apiauth: ImplicitRedirect: not an implicit request")
	}
	values := url.Values{}
	var accessToken string
	if req.ResponseType == ResponseTypeIDTokenToken {
		at, err := h.Implicit.Issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{Subject: subject, Scopes: req.Scopes(), ClientID: req.ClientID})
		if err != nil {
			return "", fmt.Errorf("access token: %w", err)
		}
		accessToken = at.Token
		values.Set("access_token", at.Token)
		values.Set("token_type", "Bearer")
		values.Set("expires_in", strconv.FormatInt(at.ExpiresIn, 10))
		values.Set("scope", req.Scope)
	}
	idt, err := h.Implicit.IDTokens.CreateIDToken(ctx, &CreateIDTokenRequest{
		Subject: subject, ClientID: req.ClientID, Scopes: req.Scopes(), Nonce: req.Nonce, AuthTime: req.AuthTime, ACR: req.ACR, AMR: req.AMR,
		AccessToken: accessToken, RequestedClaims: req.IDTokenClaims, ScopeClaims: accessToken == "",
	})
	if err != nil {
		return "", fmt.Errorf("id token: %w", err)
	}
	values.Set("id_token", idt.Token)
	if req.State != "" {
		values.Set("state", req.State)
	}
	if h.EmitIssParameter && h.IssuerURL != "" {
		values.Set("iss", h.IssuerURL)
	}
	if h.RedirectOverride != nil {
		h.RedirectOverride(values)
	}
	return appendFragment(req.RedirectURI, values)
}

// appendFragment sets values as base's fragment, replacing any it had
// (registered redirect URIs carry none, RFC 6749 §3.1.2).
func appendFragment(base string, values url.Values) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String() + "#" + values.Encode(), nil
}
