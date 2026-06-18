package apiauth

// This file used to host APIAuth.handleAuthorizationCodeGrant — the
// token-endpoint branch for grant_type=authorization_code. After #298
// the redemption flow lives behind the AuthorizationCodeGranter
// interface; the implementation is in authorize_granter.go and the
// HTTP shim is in token_endpoint.go.
//
// AuthorizationCodeGrantType (the OAuth 2.0 wire identifier for the
// grant) lives in authorize.go alongside the rest of the
// authorization-code primitives.
