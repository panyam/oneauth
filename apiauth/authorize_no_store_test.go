package apiauth

// The redirect that carries an authorization code is not cached (RFC 6749
// §10.5: codes are short-lived single-use credentials).
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-10.5
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoStore_AuthorizeRedirectWithCode(t *testing.T) {
	mux, _ := newAuthorizeMux(t, "user-1")
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+authorizeQuery(t).Encode(), nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}
