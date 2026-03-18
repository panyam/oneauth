package httpauth_test

import (
	"github.com/panyam/oneauth/httpauth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// okHandler is a simple handler that always returns 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
})

func newCSRF() *httpauth.CSRFMiddleware {
	return &httpauth.CSRFMiddleware{}
}

// getCookie extracts a named cookie from a recorded response.
func getCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestCSRFProtectSetsTokenOnGET verifies that a GET request receives a csrf_token
// cookie and the token is available via the request context.
func TestCSRFProtectSetsTokenOnGET(t *testing.T) {
	csrf := newCSRF()
	var contextToken string

	handler := csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextToken = httpauth.CSRFToken(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/form", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	cookie := getCookie(rr.Result(), "csrf_token")
	require.NotNil(t, cookie, "csrf_token cookie should be set")
	assert.Len(t, cookie.Value, 64, "token should be 64 hex chars (32 bytes)")
	assert.Equal(t, cookie.Value, contextToken, "context token should match cookie")
}

// TestCSRFProtectRejectsPostWithoutToken verifies that a POST without any CSRF
// token is rejected with 403.
func TestCSRFProtectRejectsPostWithoutToken(t *testing.T) {
	csrf := newCSRF()
	handler := csrf.Protect(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestCSRFProtectAcceptsValidFormToken verifies that a POST with a matching
// csrf_token form field passes through.
func TestCSRFProtectAcceptsValidFormToken(t *testing.T) {
	csrf := newCSRF()
	handler := csrf.Protect(okHandler)

	// Step 1: GET to obtain the token
	getReq := httptest.NewRequest(http.MethodGet, "/form", nil)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)

	cookie := getCookie(getRR.Result(), "csrf_token")
	require.NotNil(t, cookie)
	token := cookie.Value

	// Step 2: POST with form field + cookie
	form := url.Values{"csrf_token": {token}}
	postReq := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	postRR := httptest.NewRecorder()
	handler.ServeHTTP(postRR, postReq)

	assert.Equal(t, http.StatusOK, postRR.Code)
}

// TestCSRFProtectAcceptsValidHeaderToken verifies that a POST with a matching
// X-CSRF-Token header passes through.
func TestCSRFProtectAcceptsValidHeaderToken(t *testing.T) {
	csrf := newCSRF()
	handler := csrf.Protect(okHandler)

	// GET to obtain token
	getReq := httptest.NewRequest(http.MethodGet, "/form", nil)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	token := getCookie(getRR.Result(), "csrf_token").Value

	// POST with header + cookie
	postReq := httptest.NewRequest(http.MethodPost, "/submit", nil)
	postReq.Header.Set("X-CSRF-Token", token)
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	postRR := httptest.NewRecorder()
	handler.ServeHTTP(postRR, postReq)

	assert.Equal(t, http.StatusOK, postRR.Code)
}

// TestCSRFProtectRejectsMismatchedToken verifies that a POST with a wrong
// token is rejected with 403.
func TestCSRFProtectRejectsMismatchedToken(t *testing.T) {
	csrf := newCSRF()
	handler := csrf.Protect(okHandler)

	// GET to obtain token
	getReq := httptest.NewRequest(http.MethodGet, "/form", nil)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	token := getCookie(getRR.Result(), "csrf_token").Value

	// POST with wrong form token
	form := url.Values{"csrf_token": {"wrong-token-value"}}
	postReq := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	postRR := httptest.NewRecorder()
	handler.ServeHTTP(postRR, postReq)

	assert.Equal(t, http.StatusForbidden, postRR.Code)
}

// TestCSRFProtectExemptBearer verifies that requests with an Authorization: Bearer
// header skip CSRF validation entirely.
func TestCSRFProtectExemptBearer(t *testing.T) {
	csrf := newCSRF()
	handler := csrf.Protect(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/action", nil)
	req.Header.Set("Authorization", "Bearer some-jwt-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestCSRFTokenFromContext verifies that CSRFToken returns an empty string
// when no middleware is active.
func TestCSRFTokenFromContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Equal(t, "", httpauth.CSRFToken(req))
}

// TestCSRFTemplateField verifies the hidden input field output.
func TestCSRFTemplateField(t *testing.T) {
	csrf := newCSRF()
	var field string

	handler := csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		field = string(httpauth.CSRFTemplateField(r))
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/form", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Contains(t, field, `<input type="hidden" name="csrf_token"`)
	assert.Contains(t, field, `value="`)
}

// TestCSRFProtectAllowsSafeMethodsWithoutToken verifies that GET, HEAD, and
// OPTIONS pass through even without a token.
func TestCSRFProtectAllowsSafeMethodsWithoutToken(t *testing.T) {
	csrf := newCSRF()
	handler := csrf.Protect(okHandler)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/page", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "method %s should pass", method)
	}
}

// TestCSRFProtectRejectsMissingCookie verifies that a POST with a header token
// but no cookie is rejected.
func TestCSRFProtectRejectsMissingCookie(t *testing.T) {
	csrf := newCSRF()
	handler := csrf.Protect(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	// No cookie set
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestCSRFCustomErrorHandler verifies that a custom ErrorHandler is called
// on CSRF failure.
func TestCSRFCustomErrorHandler(t *testing.T) {
	csrf := &httpauth.CSRFMiddleware{
		ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			w.Write([]byte("custom error"))
		},
	}
	handler := csrf.Protect(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTeapot, rr.Code)
	assert.Equal(t, "custom error", rr.Body.String())
}

// TestCSRFProtectReusesExistingCookie verifies that subsequent GETs reuse the
// same token from the cookie rather than generating a new one.
func TestCSRFProtectReusesExistingCookie(t *testing.T) {
	csrf := newCSRF()
	var token1, token2 string

	handler := csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First GET — generates new token
	req1 := httptest.NewRequest(http.MethodGet, "/form", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	cookie := getCookie(rr1.Result(), "csrf_token")
	require.NotNil(t, cookie)
	token1 = cookie.Value

	// Second GET — with cookie from first request
	req2 := httptest.NewRequest(http.MethodGet, "/form", nil)
	req2.AddCookie(&http.Cookie{Name: "csrf_token", Value: token1})
	rr2 := httptest.NewRecorder()

	// Capture the context token
	handler2 := csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token2 = httpauth.CSRFToken(r)
		w.WriteHeader(http.StatusOK)
	}))
	handler2.ServeHTTP(rr2, req2)

	assert.Equal(t, token1, token2, "should reuse existing cookie token")
	// Should NOT set a new cookie since one already exists
	newCookie := getCookie(rr2.Result(), "csrf_token")
	assert.Nil(t, newCookie, "should not set a new cookie when one already exists")
}
