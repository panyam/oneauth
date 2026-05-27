package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TokenExchangeGrantType is the RFC 8693 grant_type value sent at the
// token endpoint to request a token exchange.
const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// TokenExchangeRequest models the inputs to RFC 8693 §2.1. SubjectToken
// and SubjectTokenType are required; everything else is optional and is
// omitted from the wire request when unset.
type TokenExchangeRequest struct {
	// ClientID identifies the client to the AS. Required.
	ClientID string

	// ClientSecret authenticates the client when ClientAssertion is nil.
	ClientSecret string

	// ClientAssertion, when non-nil, switches client authentication to
	// the private_key_jwt path (RFC 7521 §4.2 / RFC 7523 §2.2).
	ClientAssertion *ClientAssertionConfig

	// SubjectToken carries the security token representing the party on
	// whose behalf the request is made. Required (RFC 8693 §2.1).
	SubjectToken string

	// SubjectTokenType identifies the kind of the SubjectToken (e.g.
	// urn:ietf:params:oauth:token-type:id_token). Required.
	SubjectTokenType string

	// ActorToken is an optional second token identifying the acting
	// party — used in delegation flows where the actor differs from the
	// subject (RFC 8693 §1.2).
	ActorToken string

	// ActorTokenType identifies the kind of the ActorToken. Required
	// when ActorToken is set.
	ActorTokenType string

	// RequestedTokenType identifies the kind of token the caller wants
	// the AS to issue. Optional — when omitted the AS chooses.
	RequestedTokenType string

	// Audience names the relying parties intended to consume the
	// issued token (RFC 8693 §2.1). Emitted as repeated `audience`
	// form values when more than one is provided.
	Audience []string

	// Resource is the RFC 8707 resource indicator. Emitted as repeated
	// `resource` form values per §2.
	Resource []string

	// Scope requests specific scopes for the issued token. Encoded as a
	// single space-delimited `scope` form value per RFC 6749 §3.3.
	Scope []string
}

// TokenExchangeResponse is the parsed RFC 8693 §2.2 response. The wire
// format is a JSON object with snake_case keys; `Scope` is split from
// the space-delimited string into a slice for convenience.
type TokenExchangeResponse struct {
	AccessToken     string
	IssuedTokenType string
	TokenType       string
	ExpiresIn       int
	RefreshToken    string
	Scope           []string
}

// rawTokenExchangeResponse mirrors the on-the-wire JSON keys so the
// public TokenExchangeResponse can present `Scope` as a slice without
// callers parsing a space-delimited string by hand.
type rawTokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

// TokenExchange performs an RFC 8693 token exchange. The caller can
// authenticate via shared secret (ClientID + ClientSecret) or via
// private_key_jwt (ClientID + ClientAssertion). Returns the parsed
// response including `issued_token_type`.
func (c *AuthClient) TokenExchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("TokenExchange: req is required")
	}
	if req.SubjectToken == "" || req.SubjectTokenType == "" {
		return nil, fmt.Errorf("TokenExchange: SubjectToken and SubjectTokenType are required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	tokenEndpoint := c.serverURL + c.tokenEndpoint
	if c.cachedASMeta != nil && c.cachedASMeta.TokenEndpoint != "" {
		tokenEndpoint = c.cachedASMeta.TokenEndpoint
	}

	data := url.Values{
		"grant_type":         {TokenExchangeGrantType},
		"subject_token":      {req.SubjectToken},
		"subject_token_type": {req.SubjectTokenType},
	}
	if req.ActorToken != "" {
		data.Set("actor_token", req.ActorToken)
	}
	if req.ActorTokenType != "" {
		data.Set("actor_token_type", req.ActorTokenType)
	}
	if req.RequestedTokenType != "" {
		data.Set("requested_token_type", req.RequestedTokenType)
	}
	for _, a := range req.Audience {
		data.Add("audience", a)
	}
	for _, r := range req.Resource {
		data.Add("resource", r)
	}
	if len(req.Scope) > 0 {
		data.Set("scope", strings.Join(req.Scope, " "))
	}

	httpReq, err := c.buildTokenRequest(ctx, tokenEndpoint, data, req.ClientID, req.ClientSecret, req.ClientAssertion)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Transport: c.baseTransport} // bypass refreshTransport to avoid auth loop
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw rawTokenExchangeResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode token exchange response: %w", err)
	}
	var scopes []string
	if raw.Scope != "" {
		scopes = strings.Fields(raw.Scope)
	}
	return &TokenExchangeResponse{
		AccessToken:     raw.AccessToken,
		IssuedTokenType: raw.IssuedTokenType,
		TokenType:       raw.TokenType,
		ExpiresIn:       raw.ExpiresIn,
		RefreshToken:    raw.RefreshToken,
		Scope:           scopes,
	}, nil
}

// buildTokenRequest assembles a POST request to the token endpoint with
// the supplied form payload + the negotiated client authentication
// method. Shared by TokenExchange and JwtBearerGrant — both are
// non-credential-persisting flows that emit the same form/auth shape
// as ClientCredentials but return shape-specific responses, so they
// can't share executeTokenRequest's persistence path.
func (c *AuthClient) buildTokenRequest(ctx context.Context, tokenEndpoint string, data url.Values, clientID, clientSecret string, assertion *ClientAssertionConfig) (*http.Request, error) {
	if assertion != nil {
		signed, err := MintClientAssertion(clientID, tokenEndpoint, *assertion)
		if err != nil {
			return nil, fmt.Errorf("mint client_assertion: %w", err)
		}
		applyAssertionToForm(clientID, signed, data)
		httpReq, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return httpReq, nil
	}
	var asMethods []string
	if c.cachedASMeta != nil {
		asMethods = c.cachedASMeta.TokenEndpointAuthMethods
	}
	authMethod := SelectAuthMethod(clientSecret, asMethods)
	applyAuthToForm(authMethod, clientID, clientSecret, data)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authMethod == AuthMethodClientSecretBasic {
		httpReq.SetBasicAuth(clientID, clientSecret)
	}
	return httpReq, nil
}

