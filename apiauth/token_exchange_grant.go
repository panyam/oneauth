package apiauth

// TokenExchangeGrantType is the OAuth grant type URI for OAuth 2.0
// Token Exchange (RFC 8693 §2.1). A client presents a `subject_token`
// representing the party on whose behalf the request is made and the
// AS issues a new token (typically narrower in scope or audience).
//
// Common use case: enterprise-managed identity chains. A federated IdP
// issues a JWT about an employee; the employee's MCP client trades that
// JWT for an MCP-scoped access token via this grant.
//
// See: https://www.rfc-editor.org/rfc/rfc8693
const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// RFC 8693 §3 token type URIs.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
)

// The grant flow lives behind the TokenExchanger interface; the
// implementation is in token_exchange_granter.go and the HTTP shim is
// in token_endpoint.go.
