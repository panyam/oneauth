package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The pages of the authorization flow send Cross-Origin-Opener-Policy
// unsafe-none, and every other response keeps same-origin. A client that
// opens /authorize in a popup (an SPA's signinPopup, or OAuch) needs the
// popup to keep its window.opener: with same-origin, the browser cuts the
// popup off when it reaches oneauth, so the callback page can't hand the
// result back to the window that opened it (issue 497).
//
// See: https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies
// See: https://github.com/panyam/oneauth/issues/497
func TestAuthFlowPagesAllowPopupOpeners(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})
	h := withSecurityHeaders(inner)
	for path, want := range map[string]string{
		"/authorize":                   "unsafe-none",
		"/authorize?client_id=x":       "unsafe-none",
		"/auth/login":                  "unsafe-none",
		"/auth/signup":                 "unsafe-none",
		"/device":                      "same-origin",
		"/":                            "same-origin",
		"/api/token":                   "same-origin",
		"/.well-known/jwks.json":       "same-origin",
		"/authorized-but-not-the-flow": "same-origin",
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, want, rr.Header().Get("Cross-Origin-Opener-Policy"), path)
		assert.NotEmpty(t, rr.Header().Get("Content-Security-Policy"), "%s keeps the rest of the hardening", path)
	}
}
