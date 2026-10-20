package main

import (
	"fmt"

	"github.com/panyam/oneauth/apiauth"
)

// serverASMetadata is the RFC 8414 document for this server, before the
// device flow and DPoP add their parts. It advertises only what the server
// mounts: the code response type, RFC 9207 iss and the "none" auth method
// (public clients redeeming codes) only when /authorize is on, PAR when
// it's enabled, and under fapi2 only what FAPI 2.0 allows.
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
		if cfg.CodeFlow.OIDC {
			// OIDC Discovery §3: userinfo_endpoint is RECOMMENDED and
			// id_token_signing_alg_values_supported REQUIRED.
			meta.UserinfoEndpoint = baseURL + "/userinfo"
			meta.IDTokenSigningAlgValuesSupported = []string{cfg.JWT.SigningAlg}
		}
		if cfg.CodeFlow.PAR.Enabled {
			meta.PushedAuthorizationRequestEndpoint = baseURL + "/par"
			if cfg.CodeFlow.PAR.Required || cfg.FAPI2 {
				required := true
				meta.RequirePushedAuthorizationRequests = &required
			}
		}
	}
	if cfg.FAPI2 {
		// FAPI 2.0 §5.3.2.1 #6 and §5.4.1: private_key_jwt only, with an
		// algorithm the profile allows and oneauth verifies.
		meta.TokenEndpointAuthMethods = []string{"private_key_jwt"}
		meta.TokenEndpointAuthSigningAlgValuesSupported = []string{"ES256"}
	}
	return meta
}

// baseGrantTypes is the grant_types_supported list before the device and
// code flows add theirs. FAPI 2.0 §5.3.2.1 #2 rules out the password
// grant.
func baseGrantTypes(cfg *Config) []string {
	if cfg.FAPI2 {
		return []string{"refresh_token", "client_credentials"}
	}
	return []string{"password", "refresh_token", "client_credentials"}
}

// checkOIDC refuses code_flow.oidc without an asymmetric signing key: a
// client verifies an ID token against the JWKS, which publishes no HMAC
// secret (OIDC Core §10.1 signs an HMAC ID token with the client's own
// secret instead).
func checkOIDC(cfg *Config) error {
	if !cfg.CodeFlow.OIDC {
		return nil
	}
	if !cfg.CodeFlow.Enabled {
		return fmt.Errorf("code_flow.oidc needs code_flow.enabled: ID tokens come from the authorization code grant")
	}
	if alg := cfg.JWT.SigningAlg; alg != "RS256" && alg != "ES256" {
		if alg == "" {
			alg = "HS256 (the default)"
		}
		return fmt.Errorf("code_flow.oidc needs jwt.signing_alg RS256 or ES256, got %s: clients verify ID tokens against the JWKS, which has no HMAC secret", alg)
	}
	return nil
}

// checkFAPI2 refuses a fapi2 config the server can't honor: FAPI 2.0
// needs sender-constrained tokens (dpop), an access-token signing algorithm
// it allows, and, when /authorize is served, PAR.
func checkFAPI2(cfg *Config) error {
	if !cfg.FAPI2 {
		return nil
	}
	if cfg.JWT.SigningAlg != "ES256" {
		alg := cfg.JWT.SigningAlg
		if alg == "" {
			alg = "HS256 (the default)"
		}
		return fmt.Errorf("fapi2 needs jwt.signing_alg: ES256, got %s: FAPI 2.0 §5.4.1 allows PS256, ES256 and EdDSA, and ES256 is the one oneauth signs with (PS256 is issue 330)", alg)
	}
	if !cfg.DPoP.Enabled {
		return fmt.Errorf("fapi2 needs dpop.enabled: FAPI 2.0 §5.3.2.1 allows sender-constrained access tokens only")
	}
	if cfg.CodeFlow.Enabled && !cfg.CodeFlow.PAR.Enabled {
		return fmt.Errorf("fapi2 with code_flow needs code_flow.par.enabled: FAPI 2.0 §5.3.2.2 accepts authorization requests only through PAR")
	}
	return nil
}
