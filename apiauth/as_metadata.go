package apiauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ASServerMetadata describes an OAuth 2.0 Authorization Server per RFC 8414
// and OpenID Connect Discovery 1.0 §4. RFC 8414 §3 mandates this metadata
// be served at /.well-known/oauth-authorization-server; OIDC Discovery
// places the same document at /.well-known/openid-configuration. Use
// MountASMetadata to register both paths in one call.
//
// This is metadata-only — serving this does NOT make the server a full OIDC
// provider. It simply advertises what endpoints exist (token, JWKS,
// introspection, etc.) so standard client libraries can discover them.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
type ASServerMetadata struct {
	// Required
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`

	// Recommended
	JWKSURI string `json:"jwks_uri,omitempty"`

	// Optional endpoints
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`

	// Supported features
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"` // RFC 9396
	ScopesSupported                    []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported        []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	SubjectTypesSupported         []string `json:"subject_types_supported,omitempty"`

	// AuthorizationResponseIssParameterSupported advertises RFC 9207
	// support — when true, the AS includes an `iss` query parameter on
	// every authorization response (both successful redirects with `code`
	// and error redirects). Pointer semantics distinguish absence (omit
	// from JSON) from explicit `false` (advertised as not supported).
	//
	// RFC 9207 §3:
	//   https://www.rfc-editor.org/rfc/rfc9207#section-3
	//
	// Setting this true on an AS that does NOT actually emit `iss` in
	// authorization responses is a spec violation — clients keying off
	// the advertisement will fail to validate.
	AuthorizationResponseIssParameterSupported *bool `json:"authorization_response_iss_parameter_supported,omitempty"`

	// CacheMaxAge controls the Cache-Control max-age in seconds.
	// Defaults to 3600 (1 hour). Not serialized to JSON.
	CacheMaxAge int `json:"-"`
}

// NewASMetadataHandler returns an http.Handler that serves Authorization
// Server metadata JSON. The handler is path-agnostic — register it at
// whichever well-known path you need, or use MountASMetadata to register
// at both required paths at once.
//
// The handler:
//   - Responds to GET only (405 for other methods)
//   - Sets Content-Type: application/json
//   - Sets Cache-Control: public, max-age=<CacheMaxAge>
//   - Pre-serializes the response (metadata is static)
func NewASMetadataHandler(meta *ASServerMetadata) http.Handler {
	maxAge := meta.CacheMaxAge
	if maxAge == 0 {
		maxAge = 3600
	}

	body, err := json.Marshal(meta)
	if err != nil {
		panic(fmt.Sprintf("apiauth: failed to marshal ASServerMetadata: %v", err))
	}

	cacheHeader := fmt.Sprintf("public, max-age=%d", maxAge)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", cacheHeader)
		w.Write(body)
	})
}

// MountASMetadata registers AS metadata at both well-known paths required
// by the OAuth/OIDC ecosystem:
//
//   - /.well-known/oauth-authorization-server (RFC 8414 §3, MUST)
//   - /.well-known/openid-configuration       (OIDC Discovery 1.0 §4)
//
// Both paths serve the same handler, so the documents are byte-identical.
// OAuth-only clients (which know about RFC 8414 but not OIDC Discovery)
// and OIDC clients (which look up openid-configuration) can both
// auto-discover the AS without falling back.
//
// Callers that want only one path can register NewASMetadataHandler
// directly. This helper is the recommended default.
//
// See:
//   - RFC 8414 §3 (https://www.rfc-editor.org/rfc/rfc8414#section-3)
//   - OIDC Discovery 1.0 §4
func MountASMetadata(mux *http.ServeMux, meta *ASServerMetadata) {
	h := NewASMetadataHandler(meta)
	mux.Handle("GET /.well-known/oauth-authorization-server", h)
	mux.Handle("GET /.well-known/openid-configuration", h)
}
