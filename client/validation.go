package client

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateHTTPS checks that Authorization Server endpoints use HTTPS.
// Localhost URLs are exempt for development and testing.
// Returns nil if metadata is nil (nothing to validate).
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2.1
func ValidateHTTPS(meta *ASMetadata) error {
	if meta == nil {
		return nil
	}
	endpoints := []struct{ name, url string }{
		{"authorization_endpoint", meta.AuthorizationEndpoint},
		{"token_endpoint", meta.TokenEndpoint},
	}
	for _, ep := range endpoints {
		if ep.url == "" {
			continue
		}
		if IsLocalhost(ep.url) {
			continue
		}
		if !strings.HasPrefix(ep.url, "https://") {
			return fmt.Errorf("AS %s must be HTTPS: %s", ep.name, ep.url)
		}
	}
	return nil
}

// IsLocalhost returns true if the URL points to a loopback address
// (localhost, 127.0.0.1, or ::1). This is used to exempt local development
// servers from HTTPS enforcement.
//
// See: https://www.rfc-editor.org/rfc/rfc8252#section-8.3
func IsLocalhost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// ValidateCIMDURL validates a Client ID Metadata Document URL.
// Per draft-ietf-oauth-client-id-metadata-document:
//   - MUST use HTTPS (except localhost for development/testing)
//   - MUST contain a non-root path (the URL must identify a specific document)
//
// See: https://drafts.aaronpk.com/draft-parecki-oauth-client-id-metadata-document/draft-parecki-oauth-client-id-metadata-document.html
func ValidateCIMDURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid CIMD URL: %w", err)
	}
	if !IsLocalhost(rawURL) && u.Scheme != "https" {
		return fmt.Errorf("CIMD URL must use https: %s", rawURL)
	}
	if u.Path == "" || u.Path == "/" {
		return fmt.Errorf("CIMD URL must contain a path: %s", rawURL)
	}
	return nil
}
