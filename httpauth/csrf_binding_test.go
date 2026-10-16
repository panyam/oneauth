package httpauth_test

// CSRF beyond double-submit, issue 408: a same-site page (a sibling
// subdomain) can set the CSRF cookie and post the matching value, so the
// middleware also checks where the request came from and, given a session,
// binds the token to it.
//
// See: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie-recommended
// See: https://www.w3.org/TR/fetch-metadata/
// See: https://cwe.mitre.org/data/definitions/352.html
// See: https://github.com/panyam/oneauth/issues/408

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/httpauth"
)

func csrfOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// tokenFrom runs a GET through the middleware and returns the CSRF token
// it handed out.
func tokenFrom(t *testing.T, h http.Handler) string {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://app.example/form", nil))
	for _, c := range rr.Result().Cookies() {
		if c.Name == "csrf_token" {
			return c.Value
		}
	}
	t.Fatal("no csrf cookie")
	return ""
}

func postWith(h http.Handler, token string, headers map[string]string) int {
	req := httptest.NewRequest(http.MethodPost, "http://app.example/form", strings.NewReader(url.Values{"csrf_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// See: https://www.w3.org/TR/fetch-metadata/#sec-fetch-site-header
func TestCSRF_RequestsFromElsewhereAreRefused(t *testing.T) {
	m := &httpauth.CSRFMiddleware{}
	h := m.Protect(csrfOK())
	token := tokenFrom(t, h)

	for site, want := range map[string]int{"same-origin": 200, "none": 200, "same-site": 403, "cross-site": 403} {
		assert.Equal(t, want, postWith(h, token, map[string]string{"Sec-Fetch-Site": site}), "Sec-Fetch-Site %s", site)
	}
	// Without fetch metadata, the Origin header decides.
	assert.Equal(t, 403, postWith(h, token, map[string]string{"Origin": "https://evil.app.example"}), "a sibling subdomain")
	assert.Equal(t, 200, postWith(h, token, map[string]string{"Origin": "https://app.example"}), "this site")
	assert.Equal(t, 200, postWith(h, token, nil), "neither header: older clients still work")

	m.TrustedOrigins = []string{"https://admin.app.example"}
	assert.Equal(t, 200, postWith(h, token, map[string]string{"Origin": "https://admin.app.example"}), "a trusted origin")
}

// A token minted for one session doesn't work for another, and a value
// an attacker chose (cookie and field alike) works for none.
//
// See: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie-recommended
func TestCSRF_TokenIsBoundToTheSession(t *testing.T) {
	session := "session-a"
	m := &httpauth.CSRFMiddleware{SessionID: func(*http.Request) string { return session }}
	h := m.Protect(csrfOK())
	token := tokenFrom(t, h)
	require.Equal(t, 200, postWith(h, token, nil), "the session's own token")

	session = "session-b"
	assert.Equal(t, 403, postWith(h, token, nil), "another session's token")
	assert.Equal(t, 403, postWith(h, "attacker-chosen-value", nil), "a tossed cookie with a matching field")
}
