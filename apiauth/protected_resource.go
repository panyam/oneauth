package apiauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ProtectedResourceMetadata describes an OAuth 2.0 Protected Resource per RFC 9728.
// Resource servers serve this at GET /.well-known/oauth-protected-resource so
// clients can auto-discover which authorization servers are trusted, what scopes
// are supported, what token formats are accepted, and which signing algorithms
// are used.
//
// Required fields: Resource and AuthorizationServers.
// All other fields are optional and omitted from JSON when empty.
//
// See: https://www.rfc-editor.org/rfc/rfc9728
type ProtectedResourceMetadata struct {
	// Resource is the resource server's identifier (its base URL).
	// REQUIRED per RFC 9728 §3.
	Resource string `json:"resource"`

	// AuthorizationServers lists the authorization servers that the resource
	// server trusts to issue tokens. REQUIRED per RFC 9728 §3.
	AuthorizationServers []string `json:"authorization_servers"`

	// ScopesSupported lists the OAuth 2.0 scopes that this resource server
	// understands. Optional.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// TokenFormatsSupported lists the token formats accepted (e.g., "jwt").
	// Optional.
	TokenFormatsSupported []string `json:"token_formats_supported,omitempty"`

	// SigningAlgsSupported lists the JWS signing algorithms the resource server
	// supports for validating tokens (e.g., "RS256", "ES256", "HS256").
	// Optional.
	SigningAlgsSupported []string `json:"resource_signing_alg_values_supported,omitempty"`

	// DocumentationURI points to human-readable documentation for the resource
	// server's API. Optional.
	DocumentationURI string `json:"resource_documentation,omitempty"`

	// IntrospectionEndpoint is the URL of the token introspection endpoint
	// (RFC 7662) that can be used to validate tokens for this resource.
	// Optional — included when the resource server supports introspection.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// CacheMaxAge controls the Cache-Control max-age header in seconds.
	// Defaults to 3600 (1 hour) if zero. Not serialized to JSON.
	CacheMaxAge int `json:"-"`
}

// MountProtectedResource mounts the PRM endpoint on the given mux and
// optionally proxies AS metadata at the RFC 8414 well-known path. This
// ensures that clients which only try RFC 8414 discovery (and don't fall
// back to OIDC discovery) can find the AS metadata via the resource server.
//
// Spec references:
//   - RFC 9728 §3: PRM at /.well-known/oauth-protected-resource
//     https://www.rfc-editor.org/rfc/rfc9728#section-3
//   - RFC 8414 §3: AS metadata at /.well-known/oauth-authorization-server
//     https://www.rfc-editor.org/rfc/rfc8414#section-3
//   - MCP Auth (2025-11-25): clients discover AS via PRM → RFC 8414
//     https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
//
// When proxyASMetadata is true, for each URL in AuthorizationServers:
//   - Fetches the AS's OIDC discovery document (with RFC 8414 fallback)
//   - Caches and serves it at /.well-known/oauth-authorization-server on the resource server
//   - Also serves path-based RFC 8414 (e.g., /.well-known/oauth-authorization-server/realms/foo)
//
// This bridges OIDC-only providers (Keycloak, Auth0) that don't natively
// serve RFC 8414 metadata.
//
// Usage:
//
//	MountProtectedResource(mux, meta, true)
//	// PRM at: /.well-known/oauth-protected-resource
//	// AS metadata at: /.well-known/oauth-authorization-server (proxied)
func MountProtectedResource(mux *http.ServeMux, meta *ProtectedResourceMetadata, proxyASMetadata bool, pathPrefix ...string) {
	// Mount PRM
	prmPath := "/.well-known/oauth-protected-resource"
	if len(pathPrefix) > 0 && pathPrefix[0] != "" {
		mux.Handle(prmPath+pathPrefix[0], NewProtectedResourceHandler(meta))
	}
	mux.Handle(prmPath, NewProtectedResourceHandler(meta))

	if !proxyASMetadata {
		return
	}

	// Mount RFC 8414 AS metadata proxy for each authorization server.
	// Clients that discover the PRM and try RFC 8414 at the AS URL will
	// get 404 from OIDC-only providers. They may retry at the resource
	// server URL, where this proxy serves the cached metadata.
	for _, asURL := range meta.AuthorizationServers {
		proxy := NewASMetadataProxy(asURL, 0)
		_, asPath := splitASOriginPath(asURL)

		if asPath != "" {
			// Path-based AS (e.g., Keycloak realms):
			// /.well-known/oauth-authorization-server/realms/foo
			mux.Handle("/.well-known/oauth-authorization-server"+asPath, proxy)
		}
		// Also mount at the simple path for non-path-based AS or as fallback
		mux.Handle("/.well-known/oauth-authorization-server", proxy)
	}
}

// NewProtectedResourceHandler returns an http.Handler that serves the
// Protected Resource Metadata JSON at GET /.well-known/oauth-protected-resource.
//
// The handler:
//   - Responds to GET only (405 for other methods)
//   - Sets Content-Type: application/json
//   - Sets Cache-Control: public, max-age=<CacheMaxAge>
//   - Serializes the metadata as JSON with omitempty on optional fields
func NewProtectedResourceHandler(meta *ProtectedResourceMetadata) http.Handler {
	maxAge := meta.CacheMaxAge
	if maxAge == 0 {
		maxAge = 3600
	}

	// Pre-serialize — metadata is static, no need to re-encode per request.
	body, err := json.Marshal(meta)
	if err != nil {
		// Should never happen with valid metadata, but fail loudly if it does.
		panic(fmt.Sprintf("apiauth: failed to marshal ProtectedResourceMetadata: %v", err))
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
