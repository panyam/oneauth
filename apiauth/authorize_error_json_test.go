package apiauth

// /authorize error pages answer with an RFC 6749 §5.2-shaped JSON object
// when the client says it reads JSON, so a headless client gets the error
// code without scraping HTML. Browsers never list application/json in
// Accept and keep getting the page.
//
// See: https://github.com/panyam/oneauth/issues/393
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unregisteredRedirect(t *testing.T, accept string) *httptest.ResponseRecorder {
	t.Helper()
	mux, _ := newAuthorizeMux(t, "")
	form := authorizeQuery(t)
	form.Set("redirect_uri", "https://attacker.example/cb")
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+form.Encode(), nil)
	r.Header.Set("X-Test-Subject", "user-1")
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	return w
}

func TestAuthorizeError_JSONWhenAccepted(t *testing.T) {
	for _, accept := range []string{"application/json", "text/html, application/json;q=0.9"} {
		t.Run(accept, func(t *testing.T) {
			w := unregisteredRedirect(t, accept)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			var body map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, "unauthorized_client", body["error"])
			assert.Equal(t, "unknown client_id or redirect_uri", body["error_description"])
		})
	}
}

func TestAuthorizeError_HTMLForBrowsers(t *testing.T) {
	for _, accept := range []string{"", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "application/json;q=0"} {
		t.Run(accept, func(t *testing.T) {
			w := unregisteredRedirect(t, accept)
			assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
			assert.Contains(t, w.Body.String(), "<strong>unauthorized_client</strong>")
		})
	}
}
