package apiauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ASMetadataProxy fetches AS metadata from an authorization server's OIDC
// discovery endpoint and serves it at the RFC 8414 well-known path. This
// bridges the gap for OIDC-only providers (like Keycloak) that don't serve
// RFC 8414 metadata natively.
//
// Background:
//   - RFC 8414 §3 defines AS metadata at /.well-known/oauth-authorization-server
//     https://www.rfc-editor.org/rfc/rfc8414#section-3
//   - OIDC Discovery §4 defines it at /.well-known/openid-configuration
//     https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
//   - RFC 9728 §3 (PRM) lists authorization_servers — clients then need to
//     discover the AS's endpoints via RFC 8414 or OIDC
//     https://www.rfc-editor.org/rfc/rfc9728#section-3
//   - MCP Auth spec (2025-11-25) requires clients to discover AS via RFC 8414
//     with OIDC fallback. Some clients (VS Code) only try RFC 8414.
//     https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
//
// The proxy:
//   - Fetches lazily on first request (not at construction time)
//   - Caches the response with a configurable TTL (default 1 hour)
//   - Tries RFC 8414 first, then OIDC discovery (same fallback as client.DiscoverAS)
//   - Serves GET only (405 for other methods)
type ASMetadataProxy struct {
	issuerURL string
	cacheTTL  time.Duration

	mu        sync.RWMutex
	cached    []byte
	cachedAt  time.Time
}

// NewASMetadataProxy creates a proxy that fetches AS metadata from the given
// issuer URL. The proxy tries both RFC 8414 and OIDC discovery paths.
func NewASMetadataProxy(issuerURL string, cacheTTL time.Duration) *ASMetadataProxy {
	if cacheTTL == 0 {
		cacheTTL = time.Hour
	}
	return &ASMetadataProxy{
		issuerURL: issuerURL,
		cacheTTL:  cacheTTL,
	}
}

func (p *ASMetadataProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := p.getMetadata()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch AS metadata: %v", err), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(p.cacheTTL.Seconds())))
	w.Write(body)
}

func (p *ASMetadataProxy) getMetadata() ([]byte, error) {
	p.mu.RLock()
	if p.cached != nil && time.Since(p.cachedAt) < p.cacheTTL {
		defer p.mu.RUnlock()
		return p.cached, nil
	}
	p.mu.RUnlock()

	// Fetch fresh
	body, err := p.fetchMetadata()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.cached = body
	p.cachedAt = time.Now()
	p.mu.Unlock()

	return body, nil
}

func (p *ASMetadataProxy) fetchMetadata() ([]byte, error) {
	urls := buildASDiscoveryURLs(p.issuerURL)

	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s returned %d", url, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("read %s: %w", url, err)
			continue
		}

		// Validate it's JSON
		var check map[string]any
		if err := json.Unmarshal(body, &check); err != nil {
			lastErr = fmt.Errorf("%s: invalid JSON: %w", url, err)
			continue
		}

		return body, nil
	}

	return nil, fmt.Errorf("AS metadata discovery failed for %s: %w", p.issuerURL, lastErr)
}

// buildASDiscoveryURLs constructs the ordered list of well-known URLs to try
// for an authorization server. Tries RFC 8414 first, then OIDC discovery.
func buildASDiscoveryURLs(issuerURL string) []string {
	origin, path := splitASOriginPath(issuerURL)

	if path == "" {
		return []string{
			origin + "/.well-known/oauth-authorization-server",
			origin + "/.well-known/openid-configuration",
		}
	}

	return []string{
		origin + "/.well-known/oauth-authorization-server" + path,
		origin + path + "/.well-known/openid-configuration",
	}
}

// splitASOriginPath splits a URL into origin (scheme + host) and path.
func splitASOriginPath(rawURL string) (origin, path string) {
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 {
		return rawURL, ""
	}
	hostStart := schemeEnd + 3
	pathStart := strings.Index(rawURL[hostStart:], "/")
	if pathStart < 0 {
		return rawURL, ""
	}
	pathStart += hostStart
	return rawURL[:pathStart], rawURL[pathStart:]
}
