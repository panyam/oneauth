package apiauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ASServerMetadata describes an OAuth 2.0 Authorization Server per RFC 8414
// and OpenID Connect Discovery 1.0 §4. The auth server serves this at
// GET /.well-known/openid-configuration so OIDC-aware clients can
// auto-discover endpoints.
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
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported        []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	SubjectTypesSupported         []string `json:"subject_types_supported,omitempty"`

	// CacheMaxAge controls the Cache-Control max-age in seconds.
	// Defaults to 3600 (1 hour). Not serialized to JSON.
	CacheMaxAge int `json:"-"`
}

// NewASMetadataHandler returns an http.Handler that serves Authorization Server
// metadata JSON at GET /.well-known/openid-configuration.
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
