package client

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// JwtBearerGrantType is the RFC 7523 §2.1 grant_type value — the JWT
// bearer authorization grant. Distinct from the private_key_jwt CLIENT
// authentication method (which uses `client_assertion`); this grant
// exchanges a signed `assertion` for an access token.
const JwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// JwtBearerGrantRequest models the inputs to RFC 7523 §2.1. Client
// authentication is negotiated separately via ClientID +
// (ClientSecret | ClientAssertion) — both authentication methods may
// coexist with the bearer Assertion in the same form payload.
type JwtBearerGrantRequest struct {
	// ClientID identifies the client to the AS. Required.
	ClientID string

	// ClientSecret authenticates the client when ClientAssertion is nil.
	ClientSecret string

	// ClientAssertion, when non-nil, switches client authentication to
	// the private_key_jwt path. The resulting `client_assertion` form
	// field coexists with the bearer `assertion` below.
	ClientAssertion *ClientAssertionConfig

	// Assertion is the signed JWT presented as the authorization grant
	// (RFC 7523 §2.1). Required. Issued out-of-band — typically the
	// output of a prior token exchange or a trusted upstream IdP.
	Assertion string

	// Scope optionally narrows the requested scopes for the issued
	// access token. Space-delimited on the wire per RFC 6749 §3.3.
	Scope []string

	// Resources are RFC 8707 resource indicators emitted as repeated
	// `resource` form values.
	Resources []string
}

// JwtBearerGrant performs an RFC 7523 §2.1 jwt-bearer grant exchange.
// Returns a usable ServerCredential containing the access token.
func (c *AuthClient) JwtBearerGrant(ctx context.Context, req *JwtBearerGrantRequest) (*ServerCredential, error) {
	if req == nil {
		return nil, fmt.Errorf("JwtBearerGrant: req is required")
	}
	if req.Assertion == "" {
		return nil, fmt.Errorf("JwtBearerGrant: Assertion is required")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("JwtBearerGrant: ClientID is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	tokenEndpoint := c.serverURL + c.tokenEndpoint
	if c.cachedASMeta != nil && c.cachedASMeta.TokenEndpoint != "" {
		tokenEndpoint = c.cachedASMeta.TokenEndpoint
	}

	data := url.Values{
		"grant_type": {JwtBearerGrantType},
		"assertion":  {req.Assertion},
	}
	if len(req.Scope) > 0 {
		data.Set("scope", strings.Join(req.Scope, " "))
	}
	for _, r := range req.Resources {
		data.Add("resource", r)
	}

	httpReq, err := c.buildTokenRequest(ctx, tokenEndpoint, data, req.ClientID, req.ClientSecret, req.ClientAssertion)
	if err != nil {
		return nil, err
	}
	return c.executeTokenRequest(httpReq)
}
