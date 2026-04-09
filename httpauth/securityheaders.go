package httpauth

import "net/http"

// SecurityHeaders returns middleware that sets standard security headers
// on every response. These headers protect against common web vulnerabilities:
//
//   - HSTS: forces HTTPS connections (RFC 6797)
//   - X-Content-Type-Options: prevents MIME sniffing
//   - X-Frame-Options: prevents clickjacking
//   - Content-Security-Policy: mitigates XSS
//   - Referrer-Policy: controls referrer leakage
//   - Permissions-Policy: disables unnecessary browser APIs
//
// Usage:
//
//	mux := http.NewServeMux()
//	handler := httpauth.SecurityHeaders()(mux)
//	http.ListenAndServe(":8080", handler)
//
// See: https://owasp.org/www-project-secure-headers/
func SecurityHeaders() func(http.Handler) http.Handler {
	return SecurityHeadersWithConfig(DefaultSecurityHeadersConfig())
}

// SecurityHeadersConfig controls which security headers are set.
type SecurityHeadersConfig struct {
	// HSTS max-age in seconds. Set to 0 to disable. Default: 31536000 (1 year).
	HSTSMaxAge int
	// Include subdomains in HSTS. Default: true.
	HSTSIncludeSubDomains bool
	// X-Frame-Options value. Default: "DENY". Set to "" to disable.
	FrameOptions string
	// Content-Security-Policy value. Default: "default-src 'self'". Set to "" to disable.
	ContentSecurityPolicy string
	// Referrer-Policy value. Default: "strict-origin-when-cross-origin". Set to "" to disable.
	ReferrerPolicy string
	// Permissions-Policy value. Default: disables camera, mic, geo. Set to "" to disable.
	PermissionsPolicy string
	// Cross-Origin-Embedder-Policy value. Default: "credentialless". Set to "" to disable.
	CrossOriginEmbedderPolicy string
	// Cross-Origin-Opener-Policy value. Default: "same-origin". Set to "" to disable.
	CrossOriginOpenerPolicy string
	// Cross-Origin-Resource-Policy value. Default: "same-origin". Set to "" to disable.
	CrossOriginResourcePolicy string
}

// DefaultSecurityHeadersConfig returns secure defaults.
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		HSTSMaxAge:            31536000,
		HSTSIncludeSubDomains: true,
		FrameOptions:          "DENY",
		ContentSecurityPolicy: "default-src 'self'",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		PermissionsPolicy:         "camera=(), microphone=(), geolocation=()",
		CrossOriginEmbedderPolicy: "credentialless",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
	}
}

// SecurityHeadersWithConfig returns middleware using the provided configuration.
func SecurityHeadersWithConfig(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// Always set these
			h.Set("X-Content-Type-Options", "nosniff")

			if cfg.HSTSMaxAge > 0 {
				val := "max-age=" + itoa(cfg.HSTSMaxAge)
				if cfg.HSTSIncludeSubDomains {
					val += "; includeSubDomains"
				}
				h.Set("Strict-Transport-Security", val)
			}

			if cfg.FrameOptions != "" {
				h.Set("X-Frame-Options", cfg.FrameOptions)
			}
			if cfg.ContentSecurityPolicy != "" {
				h.Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
			}
			if cfg.ReferrerPolicy != "" {
				h.Set("Referrer-Policy", cfg.ReferrerPolicy)
			}
			if cfg.PermissionsPolicy != "" {
				h.Set("Permissions-Policy", cfg.PermissionsPolicy)
			}
			if cfg.CrossOriginEmbedderPolicy != "" {
				h.Set("Cross-Origin-Embedder-Policy", cfg.CrossOriginEmbedderPolicy)
			}
			if cfg.CrossOriginOpenerPolicy != "" {
				h.Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicy)
			}
			if cfg.CrossOriginResourcePolicy != "" {
				h.Set("Cross-Origin-Resource-Policy", cfg.CrossOriginResourcePolicy)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// itoa is a simple int-to-string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 12)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
