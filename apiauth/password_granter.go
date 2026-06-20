package apiauth

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
)

// PasswordGranter implements RFC 6749 §4.3 Resource Owner Password
// Credentials. Peer to JwtBearerGranter / TokenExchanger /
// AuthorizationCodeGranter / DeviceCodeGranter — the
// TokenEndpointHandler dispatches grant_type=password to this slot
// when it is non-nil, and returns unsupported_grant_type when it is
// nil. ROPC was retired in OAuth 2.1 §7.6; leaving the slot nil is
// strict-2.1 compliance. Wire NewPasswordGranter to opt in for OAuth
// 2.0 deployments that must keep ROPC for legacy clients.
//
// Per capability-gating umbrella #344.
type PasswordGranter interface {
	// PasswordGrant authenticates the resource owner and returns an
	// access token. Does NOT create a refresh token — the caller
	// (TokenEndpointHandler) is responsible for that with transport
	// metadata (device info, IP) the granter cannot see.
	PasswordGrant(ctx context.Context, req *PasswordGrantRequest) (*PasswordGrantResponse, error)
}

// PasswordGranterConfig wires the dependencies the default
// PasswordGranter needs. Build via NewPasswordGranter.
type PasswordGranterConfig struct {
	// Issuer is the access-token minting backend. Required.
	Issuer TokenIssuer

	// ValidateCredentials authenticates the (username, password) pair.
	// Required. Returns the User on success, an error on failure;
	// the granter maps "invalid credentials" to the RFC 6749 §5.2
	// `invalid_grant` error.
	ValidateCredentials CredentialsValidator

	// GetSubjectScopes returns the scopes the authenticated user is
	// permitted to grant. Optional — when nil, a built-in default
	// scope set (read / write / profile / offline_access) is used.
	GetSubjectScopes core.GetSubjectScopesFunc

	// Hooks are the token-lifecycle callbacks fired on issuance.
	// Zero value is fine.
	Hooks TokenHooks
}

// NewPasswordGranter returns a PasswordGranter wired with the
// supplied dependencies. Fires a one-time-per-process log when
// constructed so operators see the OAuth 2.0 escape hatch is in
// play — OAuth 2.1 §7.6 retired ROPC, and a deployment wiring
// the granter is taking deliberate responsibility for the
// password-handling surface 2.1 was designed to eliminate
// (clients see the user's primary credentials; MFA / federation
// are blocked).
func NewPasswordGranter(cfg PasswordGranterConfig) PasswordGranter {
	passwordGranterWarning.Do(func() {
		log.Printf("apiauth.NewPasswordGranter: LEGACY OAuth 2.0 PATH — Resource Owner Password Credentials grant " +
			"wired. OAuth 2.1 §7.6 retired ROPC (clients see the user's primary credentials; defeats federation, " +
			"blocks MFA and step-up auth). For strict-2.1 deployments leave OneAuthConfig.PasswordGranter nil and " +
			"use localauth/ cookie session for browser logins.")
	})
	return &defaultPasswordGranter{
		issuer:              cfg.Issuer,
		validateCredentials: cfg.ValidateCredentials,
		getSubjectScopes:    cfg.GetSubjectScopes,
		hooks:               cfg.Hooks,
	}
}

// passwordGranterWarning fires once per process the first time
// NewPasswordGranter is called. Per-process scope (not per-instance)
// because wiring the granter is a deployment-level decision; tests
// constructing many instances should see one warning, not N.
var passwordGranterWarning sync.Once

type defaultPasswordGranter struct {
	issuer              TokenIssuer
	validateCredentials CredentialsValidator
	getSubjectScopes    core.GetSubjectScopesFunc
	hooks               TokenHooks
}

func (g *defaultPasswordGranter) PasswordGrant(ctx context.Context, req *PasswordGrantRequest) (*PasswordGrantResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("PasswordGrantRequest is required")
	}
	if g.validateCredentials == nil {
		return nil, fmt.Errorf("server_error: password grant not configured")
	}

	usernameType := accounts.DetectUsernameType(req.Username)
	user, err := g.validateCredentials(req.Username, req.Password, usernameType)
	if err != nil || user == nil {
		return nil, fmt.Errorf("invalid_grant: invalid credentials")
	}

	allowedScopes := []string{core.ScopeRead, core.ScopeWrite, core.ScopeProfile, core.ScopeOffline}
	if g.getSubjectScopes != nil {
		scopes, err := g.getSubjectScopes(user.Id())
		if err != nil {
			return nil, fmt.Errorf("server_error: failed to get user scopes: %w", err)
		}
		allowedScopes = scopes
	}

	requestedScopes := req.Scopes
	if len(requestedScopes) == 0 {
		requestedScopes = allowedScopes
	}
	grantedScopes := core.IntersectScopes(requestedScopes, allowedScopes)

	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		return nil, err
	}

	tok, err := g.issuer.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject:              user.Id(),
		Scopes:               grantedScopes,
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		return nil, fmt.Errorf("server_error: %w", err)
	}

	g.hooks.fireOnIssued(user.Id(), "password")

	return &PasswordGrantResponse{
		Subject:              user.Id(),
		AccessToken:          tok.Token,
		ExpiresIn:            tok.ExpiresIn,
		GrantedScopes:        grantedScopes,
		AuthorizationDetails: req.AuthorizationDetails,
	}, nil
}
