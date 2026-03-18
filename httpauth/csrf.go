package httpauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"net/http"
	"strings"
)

type csrfContextKey struct{}

// CSRFMiddleware implements the double-submit cookie pattern for CSRF protection.
// It generates a random token stored in a cookie and validates that state-changing
// requests include a matching token in a form field or header.
//
// Bearer-token requests are exempt by default since they are not vulnerable to CSRF.
// The cookie is NOT HttpOnly so JavaScript can read it for AJAX header submission.
type CSRFMiddleware struct {
	// CookieName is the name of the CSRF cookie. Default: "csrf_token".
	CookieName string
	// FieldName is the form field name to check. Default: "csrf_token".
	FieldName string
	// HeaderName is the HTTP header to check. Default: "X-CSRF-Token".
	HeaderName string
	// MaxAge is the cookie lifetime in seconds. Default: 3600 (1 hour).
	MaxAge int
	// Secure sets the Secure flag on the cookie (for HTTPS).
	Secure bool
	// SameSite sets the SameSite attribute. Default: SameSiteStrictMode.
	SameSite http.SameSite
	// Path sets the cookie path. Default: "/".
	Path string
	// ErrorHandler is called when CSRF validation fails. Default: 403 JSON response.
	ErrorHandler http.HandlerFunc
	// ExemptFunc returns true if the request should skip CSRF validation.
	// Default: exempt requests with an Authorization: Bearer header.
	ExemptFunc func(*http.Request) bool
}

func (m *CSRFMiddleware) cookieName() string {
	if m.CookieName != "" {
		return m.CookieName
	}
	return "csrf_token"
}

func (m *CSRFMiddleware) fieldName() string {
	if m.FieldName != "" {
		return m.FieldName
	}
	return "csrf_token"
}

func (m *CSRFMiddleware) headerName() string {
	if m.HeaderName != "" {
		return m.HeaderName
	}
	return "X-CSRF-Token"
}

func (m *CSRFMiddleware) maxAge() int {
	if m.MaxAge > 0 {
		return m.MaxAge
	}
	return 3600
}

func (m *CSRFMiddleware) sameSite() http.SameSite {
	if m.SameSite != 0 {
		return m.SameSite
	}
	return http.SameSiteStrictMode
}

func (m *CSRFMiddleware) path() string {
	if m.Path != "" {
		return m.Path
	}
	return "/"
}

func (m *CSRFMiddleware) errorHandler() http.HandlerFunc {
	if m.ErrorHandler != nil {
		return m.ErrorHandler
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"CSRF token missing or invalid"}`))
	}
}

func (m *CSRFMiddleware) isExempt(r *http.Request) bool {
	if m.ExemptFunc != nil {
		return m.ExemptFunc(r)
	}
	// Default: exempt Bearer token requests
	auth := r.Header.Get("Authorization")
	return strings.HasPrefix(auth, "Bearer ") || strings.HasPrefix(auth, "bearer ")
}

func (m *CSRFMiddleware) isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// Protect returns middleware that enforces CSRF protection.
// Safe methods (GET, HEAD, OPTIONS) receive a CSRF cookie and have the token
// injected into the request context. Unsafe methods must include a matching
// token in either the form field or header.
func (m *CSRFMiddleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check exemption
		if m.isExempt(r) {
			next.ServeHTTP(w, r)
			return
		}

		if m.isSafeMethod(r.Method) {
			// Generate or reuse token
			token := m.getOrCreateToken(w, r)
			// Store in context
			ctx := context.WithValue(r.Context(), csrfContextKey{}, token)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Unsafe method: validate
		cookieToken := ""
		if c, err := r.Cookie(m.cookieName()); err == nil {
			cookieToken = c.Value
		}

		if cookieToken == "" {
			m.errorHandler()(w, r)
			return
		}

		// Check form field first, then header
		submittedToken := r.FormValue(m.fieldName())
		if submittedToken == "" {
			submittedToken = r.Header.Get(m.headerName())
		}

		if submittedToken == "" || !tokensMatch(cookieToken, submittedToken) {
			m.errorHandler()(w, r)
			return
		}

		// Valid — store token in context and proceed
		ctx := context.WithValue(r.Context(), csrfContextKey{}, cookieToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getOrCreateToken returns the existing cookie token or generates a new one.
func (m *CSRFMiddleware) getOrCreateToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(m.cookieName()); err == nil && c.Value != "" {
		return c.Value
	}

	token := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(),
		Value:    token,
		Path:     m.path(),
		MaxAge:   m.maxAge(),
		HttpOnly: false, // must be readable by JS for AJAX
		Secure:   m.Secure,
		SameSite: m.sameSite(),
	})
	return token
}

// tokensMatch compares two tokens using constant-time comparison.
func tokensMatch(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// generateCSRFToken returns a cryptographically random 64-character hex string.
func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("oneauth: failed to generate CSRF token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// CSRFToken extracts the CSRF token from the request context.
// Returns an empty string if the CSRF middleware is not active.
func CSRFToken(r *http.Request) string {
	if v, ok := r.Context().Value(csrfContextKey{}).(string); ok {
		return v
	}
	return ""
}

// CSRFTemplateField returns an HTML hidden input field containing the CSRF token.
// Use this in templates: {{.CSRFField}}
func CSRFTemplateField(r *http.Request) template.HTML {
	token := CSRFToken(r)
	return template.HTML(`<input type="hidden" name="csrf_token" value="` + template.HTMLEscapeString(token) + `">`)
}
