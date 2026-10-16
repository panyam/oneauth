package httpauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

	// TrustedOrigins are origins (scheme://host[:port]) besides this
	// server's own whose unsafe requests are accepted. Requests from any
	// other origin are refused even with a valid token, since a sibling
	// subdomain can set this cookie (CWE-352).
	TrustedOrigins []string

	// SessionID, when set, binds tokens to the session it returns: a token
	// is a nonce plus an HMAC over the session and nonce (OWASP's signed
	// double-submit), so a token minted for one session, or a value an
	// attacker set in the cookie, fails for any other. Return "" before
	// login; such tokens bind to the empty session.
	SessionID func(*http.Request) string

	// Secret keys the session-bound tokens. Instances behind one load
	// balancer need the same Secret, or a token minted by one fails on
	// another. Nil uses a random per-process key.
	Secret []byte

	secretOnce sync.Once
	secret     []byte
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

		// Unsafe method: validate. Where the request came from is checked
		// first, since a same-site page can set the cookie below.
		if !m.originAllowed(r) {
			m.errorHandler()(w, r)
			return
		}
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

		if submittedToken == "" || !tokensMatch(cookieToken, submittedToken) || !m.boundToSession(r, cookieToken) {
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
	if c, err := r.Cookie(m.cookieName()); err == nil && c.Value != "" && m.boundToSession(r, c.Value) {
		return c.Value
	}

	token := generateCSRFToken()
	if m.SessionID != nil {
		nonce := token[:32]
		token = nonce + "." + m.sign(m.SessionID(r), nonce)
	}
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

// originAllowed reports whether an unsafe request came from this site.
// Fetch metadata (Sec-Fetch-Site) is the stronger signal: same-site is
// refused too, since that's the sibling-subdomain case double-submit can't
// stop. Without it, a present Origin must name this host or a trusted
// origin. Neither header (older clients, non-browser callers) is allowed;
// the token check still applies.
func (m *CSRFMiddleware) originAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "same-site", "cross-site":
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, o := range m.TrustedOrigins {
		if origin == o {
			return true
		}
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

// boundToSession reports whether token was signed for the request's
// session. Always true when SessionID isn't set (plain double-submit).
func (m *CSRFMiddleware) boundToSession(r *http.Request, token string) bool {
	if m.SessionID == nil {
		return true
	}
	nonce, mac, ok := strings.Cut(token, ".")
	if !ok || nonce == "" {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(m.sign(m.SessionID(r), nonce)))
}

// sign is the hex HMAC-SHA256 of session and nonce under the middleware's
// secret.
func (m *CSRFMiddleware) sign(session, nonce string) string {
	m.secretOnce.Do(func() {
		m.secret = m.Secret
		if len(m.secret) == 0 {
			m.secret = make([]byte, 32)
			if _, err := rand.Read(m.secret); err != nil {
				panic("oneauth: failed to generate CSRF secret: " + err.Error())
			}
		}
	})
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(session + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}
