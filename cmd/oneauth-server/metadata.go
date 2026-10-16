package main

import "github.com/panyam/oneauth/apiauth"

// serverASMetadata is the RFC 8414 document for this server, before the
// device flow and DPoP add their parts. It advertises only what the server
// mounts: the code response type, RFC 9207 iss and the "none" auth method
// (public clients redeeming codes) only when /authorize is on.
func serverASMetadata(cfg *Config, baseURL string, codeFlow bool) *apiauth.ASServerMetadata {
	meta := &apiauth.ASServerMetadata{
		Issuer:                   baseURL,
		TokenEndpoint:            baseURL + "/api/token",
		JWKSURI:                  baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint:    baseURL + "/oauth/introspect",
		RevocationEndpoint:       baseURL + "/oauth/revoke",
		RegistrationEndpoint:     baseURL + "/apps/dcr",
		TokenEndpointAuthMethods: []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256", "ES256", "HS256", "HS384", "HS512"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		SubjectTypesSupported:                      []string{"public"},
		ScopesSupported:                            cfg.JWT.ScopesSupported,
		ClaimsSupported:                            cfg.JWT.ClaimsSupported,
		AuthorizationDetailsTypesSupported:         cfg.JWT.AuthorizationDetailsTypes,
	}
	if codeFlow {
		meta.AuthorizationEndpoint = baseURL + "/authorize"
		meta.ResponseTypesSupported = []string{"code"}
		iss := true
		meta.AuthorizationResponseIssParameterSupported = &iss
		meta.TokenEndpointAuthMethods = append(meta.TokenEndpointAuthMethods, "none")
	}
	return meta
}
