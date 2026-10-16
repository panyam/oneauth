package apiauth

// The consent page refuses to be framed (RFC 6749 §10.13).
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-10.13
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFraming_AuthorizeConsentPage(t *testing.T) {
	mux, _ := newAuthorizeMux(t, "")
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+authorizeQuery(t).Encode(), nil)
	r.Header.Set("X-Test-Subject", "alice")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
}
